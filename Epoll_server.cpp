#include <iostream>

#include <string>
#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>

#include <thread>
#include <atomic>
#include <mutex>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <fcntl.h>

#include <errno.h>
#include <csignal>

#include "http_server/http_request.h"
#include "http_server/http_response.h"
#include "http_server/router.h"

const int PORT = 8888;
const int MAX_EVENTS = 10000;      // epoll最大事件数
const int BUFFER_SIZE = 4096;      // 缓冲区大小
const int MAX_CLIENTS = 10000;     // 最大客户端数
const int EPOLL_TIMEOUT = 1000;    // epoll等待超时(ms)

// 客户端连接信息
struct ClientConnection {
    int fd;                        // socket文件描述符
    sockaddr_in addr;              // 客户端地址
    std::string ip;                // IP字符串
    int port;                      // 端口
    int id;                        // 客户端ID
    
    char buffer[BUFFER_SIZE];      // 接收缓冲区
    size_t buffer_len;             // 缓冲区数据长度
    
    std::string send_buffer;       // 发送缓冲区
    size_t send_offset;            // 发送偏移量
    
    time_t last_active;            // 最后活动时间
    
    ClientConnection(int socket_fd, sockaddr_in client_addr, int client_id) 
        : fd(socket_fd), addr(client_addr), id(client_id), 
          buffer_len(0), send_offset(0), last_active(time(nullptr)) {
        
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr.sin_addr), ip_str, INET_ADDRSTRLEN);
        ip = ip_str;
        port = ntohs(addr.sin_port);
        
        memset(buffer, 0, BUFFER_SIZE);
    }
    
    ~ClientConnection() {
        if (fd > 0) {
            close(fd);
        }
    }
    
    // 添加接收数据
    void append_data(const char* data, size_t len) {
        if (buffer_len + len < BUFFER_SIZE) {
            memcpy(buffer + buffer_len, data, len);
            buffer_len += len;
        }
    }
    
    // 获取一行数据(如果有)
    bool get_line(std::string& line) {
        for (size_t i = 0; i < buffer_len; i++) {
            if (buffer[i] == '\n') {
                line.assign(buffer, i + 1);
                // 移除已处理的数据
                memmove(buffer, buffer + i + 1, buffer_len - i - 1);
                buffer_len -= (i + 1);
                return true;
            }
        }
        return false;
    }
    
    // 添加发送数据
    void queue_send(const std::string& data) {
        send_buffer += data;
        std::cout << "Queued " << data.length() << " bytes for sending to client [" << id << "]" << std::endl;
    }
    
    // 尝试发送数据
    ssize_t try_send() {
        if (send_offset >= send_buffer.length()) {
            return 0;
        }
        
        ssize_t sent = send(fd, send_buffer.c_str() + send_offset, send_buffer.length() - send_offset, MSG_NOSIGNAL);
        
        if (sent > 0) {
            send_offset += sent;
            // 如果全部发送完成，清空缓冲区
            if (send_offset >= send_buffer.length()) {
                send_buffer.clear();
                send_offset = 0;
            }
        }
        
        return sent;
    }
};

// Epoll服务器类
class EpollServer {
private:
    int server_fd;
    int epoll_fd;
    std::atomic<int> next_client_id;
    std::atomic<int> active_clients;
    
    // 客户端连接映射
    std::map<int, std::shared_ptr<ClientConnection>> clients;
    std::mutex clients_mutex;
    
    // 统计信息
    std::atomic<long long> total_connections;
    std::atomic<long long> total_messages;
    
    // 工作线程池
    std::vector<std::thread> worker_threads;
    std::atomic<bool> running;
    
public:
    EpollServer() : next_client_id(1), active_clients(0), 
                    total_connections(0), total_messages(0), running(false) {}
    
    ~EpollServer() {
        stop();
    }
    
    // 设置非阻塞
    static bool set_nonblocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) return false;
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
    }
    
    // 初始化服务器
    bool init() {
        // 创建socket，设置为IPv4 TCP 非阻塞
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        fcntl(server_fd, F_SETFL, O_NONBLOCK);
        if (server_fd == -1) {
            std::cerr << "创建socket失败: " << strerror(errno) << std::endl;
            return false;
        }
        
        // 设置socket选项
        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
            std::cerr << "设置SO_REUSEADDR失败: " << strerror(errno) << std::endl;
            return false;
        }
        
        // 绑定地址
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(PORT);
        
        if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) == -1) {
            std::cerr << "绑定失败: " << strerror(errno) << std::endl;
            return false;
        }
        
        // 监听
        if (listen(server_fd, SOMAXCONN) == -1) {
            std::cerr << "监听失败: " << strerror(errno) << std::endl;
            return false;
        }
        
        // 创建epoll实例
        epoll_fd = epoll_create1(0);
        if (epoll_fd == -1) {
            std::cerr << "创建epoll失败: " << strerror(errno) << std::endl;
            return false;
        }
        
        // 添加服务器socket到epoll
        epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;  // 边缘触发模式
        ev.data.fd = server_fd;
        
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
            std::cerr << "添加服务器socket到epoll失败: " << strerror(errno) << std::endl;
            return false;
        }
        
        std::cout << "========================================" << std::endl;
        std::cout << "Epoll高并发服务器初始化完成" << std::endl;
        std::cout << "监听端口: " << PORT << std::endl;
        std::cout << "最大事件数: " << MAX_EVENTS << std::endl;
        std::cout << "========================================" << std::endl;
        
        return true;
    }
    
    // 处理新连接
    void handle_new_connection() {
        while (true) {  // 边缘触发需要循环accept
            sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_fd = accept4(server_fd, (sockaddr*)&client_addr, &client_len, SOCK_NONBLOCK);
            
            if (client_fd == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;  // 没有更多连接了
                }
                std::cerr << "接受连接失败: " << strerror(errno) << std::endl;
                break;
            }
            
            // 检查连接数限制
            if (active_clients >= MAX_CLIENTS) {
                std::cout << "连接数已达上限(" << MAX_CLIENTS 
                          << ")，拒绝新连接" << std::endl;
                close(client_fd);
                continue;
            }
            
            // 创建客户端连接
            int client_id = next_client_id++;
            auto client = std::make_shared<ClientConnection>(client_fd, client_addr, client_id);
            
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                clients[client_fd] = client;
            }
            
            active_clients++;
            total_connections++;
            
            // 添加到epoll监控
            epoll_event ev;
            // 不默认监听 EPOLLOUT，只有在有数据时开启
            ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
            ev.data.ptr = client.get();
            
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
                std::cerr << "添加客户端到epoll失败: " << strerror(errno) << std::endl;
                remove_client(client_fd);
                continue;
            }
            
            std::cout << "新连接 [" << client_id << "] " 
                      << client->ip << ":" << client->port 
                      << " (在线: " << active_clients 
                      << ", 总连接: " << total_connections << ")" << std::endl;
            
            // 发送欢迎消息
            // std::string welcome = "Welcome! Your ID: " + std::to_string(client_id) + "\n";
            // client->queue_send(welcome);

            // 有数据要发，启用写事件
            enable_write_event(client.get());
        }
    }
    

    // 处理客户端数据
    void handle_client_data(ClientConnection* client) {
        bool peer_closed = false;

        // 边缘触发需要循环读取
        while (true) {  
            char temp_buffer[BUFFER_SIZE];
            ssize_t count = recv(client->fd, temp_buffer, sizeof(temp_buffer), 0);
            if (count == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;  // 没有更多数据了
                }
                std::cerr << "读取数据失败: " << strerror(errno) << std::endl;
                remove_client(client->fd);
                break;
            } else if (count == 0) {
                // 对端已关闭写端（EOF），不要立刻移除，先处理已接收的数据
                peer_closed = true;
                break;
            }
            
            // 更新活动时间
            client->last_active = time(nullptr);
            
            // 添加到缓冲区
            client->append_data(temp_buffer, count);
            total_messages++;
        }
        
        // 处理缓冲区中的数据
        if (client->buffer_len > 0) {
            // 检查是否是HTTP请求
            if (is_http_request(std::string(client->buffer, client->buffer_len))) {
                // 检查HTTP请求是否完整
                if (is_http_request_complete(client->buffer, client->buffer_len)) {
                    std::string request(client->buffer, client->buffer_len);
                    handle_http_request(client, request);
                    
                    // 清空已处理的数据
                    client->buffer_len = 0;
                } else {
                    std::cout << "HTTP请求不完整，等待更多数据..." << std::endl;
                    std::cout << "当前缓冲区大小: " << client->buffer_len << " 字节" << std::endl;
                }
            } else {
                // 处理普通消息（非HTTP）
                std::string line;
                while (client->get_line(line)) {
                    process_message(client, line);
                }
            }
        }

        // 如果对端已关闭且缓冲已处理完，则关闭连接
        if (peer_closed && client->buffer_len == 0) {
            remove_client(client->fd);
        }
    }
    
    // 处理非http请求
    void process_message(ClientConnection* client, const std::string& message) {
        std::string trimmed_msg = message;
        if (!trimmed_msg.empty() && trimmed_msg.back() == '\n') {
            trimmed_msg.pop_back();
        }
        if (!trimmed_msg.empty() && trimmed_msg.back() == '\r') {
            trimmed_msg.pop_back();
        }
        
        std::cout << "客户端 [" << client->id << "]: " << trimmed_msg << std::endl;
        
        // 命令处理
        if (trimmed_msg == "exit" || trimmed_msg == "quit") {
            std::string response = "Goodbye!\n";
            client->queue_send(response);
            remove_client(client->fd);
        } else if (trimmed_msg == "count") {
            std::string response = "当前在线: " + std::to_string(active_clients) 
                                + ", 总连接: " + std::to_string(total_connections) + "\n";
            client->queue_send(response);
        } else if (trimmed_msg == "time") {
            time_t now = time(nullptr);
            std::string response = "服务器时间: " + std::string(ctime(&now));
            client->queue_send(response);
        } else if (trimmed_msg == "stats") {
            std::string response = "统计信息:\n"
                                "  在线客户端: " + std::to_string(active_clients) + "\n"
                                "  总连接数: " + std::to_string(total_connections) + "\n"
                                "  总消息数: " + std::to_string(total_messages) + "\n";
            client->queue_send(response);
        } else {
            // 默认回声
            std::string response = "回声: " + trimmed_msg + "\n";
            client->queue_send(response);
            enable_write_event(client);
        }
    }    

    // 处理http请求
    void handle_http_request(ClientConnection* client, const std::string& request_data) {
        // 解析HTTP请求
        http_request_t* req = parse_http_request(request_data.c_str(), (int)request_data.length());
        // 路由处理
        http_response_t* resp = route_request(req);
        // 转换为字符串并存入发送缓冲区
        int resp_len;
        char* resp_str = http_response_to_string(resp, &resp_len);
        client->queue_send(std::string(resp_str, resp_len));
        // 有数据待发，启用写事件
        enable_write_event(client);
        // 释放资源
        free_http_response(resp);
        free_http_request(req);
        delete[] resp_str;
    }

    // 是否是HTTP请求
    bool is_http_request(const std::string& data) {
        // 检查是否是HTTP请求（检查请求方法）
        if (data.length() < 4) return false;
        return (data.substr(0, 3) == "GET" || 
                data.substr(0, 4) == "POST" ||
                data.substr(0, 3) == "PUT" ||
                data.substr(0, 6) == "DELETE" ||
                data.substr(0, 4) == "HEAD" ||
                data.substr(0, 7) == "OPTIONS" ||
                data.substr(0, 5) == "PATCH");
    }

    // 是否是完整的HTTP请求
    bool is_http_request_complete(const char* buffer, size_t len) {
        if (len < 4) return false;
        
        // 查找头部结束标记 \r\n\r\n
        const char* end_of_headers = strstr(buffer, "\r\n\r\n");
        if (!end_of_headers) return false;
        
        // 检查是否有Content-Length
        const char* cl_header = strstr(buffer, "Content-Length:");
        if (cl_header) {
            int content_length = 0;
            sscanf(cl_header + 15, "%d", &content_length);
            
            // 计算头部长度
            size_t headers_len = end_of_headers - buffer + 4;  // +4 for \r\n\r\n
            size_t total_needed = headers_len + content_length;
            
            return len >= total_needed;
        }
        
        // 没有body的请求，头部结束就是完整请求
        return true;
    }

    // 处理发送
    void handle_client_send(ClientConnection* client) {
        ssize_t sent = client->try_send();
        if (sent == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                remove_client(client->fd);
            }
        }

        // 边缘触发下需要循环发送直到出错或返回 EAGAIN
        while (true) {
            ssize_t sent = client->try_send();
            if (sent > 0) {
                continue; // 继续发送直到 EAGAIN
            }
            if (sent == 0) {
                // 没有更多数据需要立即发送
                break;
            }
            // sent == -1: 出错或 EAGAIN
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else {
                remove_client(client->fd);
                return;
            }
        }

        // 发送完了就关闭写事件以避免无谓触发
        if (client->send_buffer.empty()) {
            disable_write_event(client);
        }
    }
    

    // 移除客户端
    void remove_client(int fd) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = clients.find(fd);
        if (it != clients.end()) {
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
            clients.erase(it);
            active_clients--;
        }
    }
    
    // 启用写事件
    void enable_write_event(ClientConnection* client) {
        epoll_event ev;
        ev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
        ev.data.ptr = client;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
    }

    // 禁用写事件
    void disable_write_event(ClientConnection* client) {
        epoll_event ev;
        ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
        ev.data.ptr = client;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
    }

    // 清理空闲连接（心跳检测）
    void cleanup_idle_connections(int idle_timeout = 300) {  // 5分钟
        time_t now = time(nullptr);
        std::vector<int> to_remove;
        
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            for (const auto& pair : clients) {
                if (now - pair.second->last_active > idle_timeout) {
                    to_remove.push_back(pair.first);
                }
            }
        }
        
        for (int fd : to_remove) {
            std::cout << "清理空闲连接: " << fd << std::endl;
            remove_client(fd);
        }
    }
    
    // 构建工作线程池
    void start_worker_threads() {
        int num_workers = std::thread::hardware_concurrency();
        if (num_workers == 0) num_workers = 4;
        
        std::cout << "启动 " << num_workers << " 个工作线程" << std::endl;
        
        for (int i = 0; i < num_workers; ++i) {
            worker_threads.emplace_back([this, i]() {worker_thread_function(i);});
        }
    }

    // 主循环
    void run() {
        running = true;
        start_worker_threads();  // 在主循环开始前启动工作线程
        
        epoll_event events[MAX_EVENTS]; // 主线程处理epoll事件
        
        while (running) {
            // 等待事件，并返回就绪事件个数nfds
            int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, EPOLL_TIMEOUT);
            
            if (nfds == -1) {
                if (errno == EINTR) {
                    continue;  // 被信号中断
                }
                std::cerr << "epoll_wait失败: " << strerror(errno) << std::endl;
                break;
            }
            
            // 处理事件
            for (int i = 0; i < nfds; ++i) {
                if (events[i].data.fd == server_fd) {
                    // 新连接到来
                    handle_new_connection();
                } else {
                    ClientConnection* client = static_cast<ClientConnection*>(events[i].data.ptr);
                    if (events[i].events & EPOLLIN) {
                        // 可读事件
                        handle_client_data(client);
                    }
                    if (events[i].events & EPOLLOUT) {
                        // 可写事件
                        handle_client_send(client);
                    }
                    if (events[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
                        // 连接关闭或错误
                        remove_client(client->fd);
                    }
                }
            }
            
            // 定期清理（每10秒）
            static time_t last_cleanup = time(nullptr);
            if (time(nullptr) - last_cleanup > 10) {
                cleanup_idle_connections();
                last_cleanup = time(nullptr);
            }
            
            // 显示状态（可选）
            static int tick = 0;
            if (++tick % 100 == 0) {
                std::cout << "[状态] 在线: " << active_clients 
                          << ", 总连接: " << total_connections 
                          << ", 消息: " << total_messages << std::endl;
            }
        }
    }
    
    // 工作线程函数（用于处理耗时任务）
    void worker_thread_function(int thread_id) {
        std::cout << "工作线程 " << thread_id << " 启动" << std::endl;
        
        // 这里可以处理耗时的业务逻辑
        // 例如：数据库操作、复杂计算等
        
        while (running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            // 示例：处理一些后台任务
            // process_background_tasks();
        }
        
        std::cout << "工作线程 " << thread_id << " 退出" << std::endl;
    }
    
    // 停止服务器
    void stop() {
        running = false;
        
        // 等待工作线程结束
        for (auto& thread : worker_threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        // 关闭所有连接
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            for (const auto& pair : clients) {
                close(pair.first);
            }
            clients.clear();
        }
        
        // 关闭epoll和服务器socket
        if (epoll_fd > 0) close(epoll_fd);
        if (server_fd > 0) close(server_fd);
        
        std::cout << "服务器已停止" << std::endl;
    }
};

int main() {
    EpollServer server;
    
    // 设置信号处理（优雅退出）
    signal(SIGINT, [](int) {
        std::cout << "\n收到中断信号，正在关闭服务器..." << std::endl;
        exit(0);
    });
    
    signal(SIGTERM, [](int) {
        std::cout << "\n收到终止信号，正在关闭服务器..." << std::endl;
        exit(0);
    });
    
    try {
        if (!server.init()) {
            std::cerr << "服务器初始化失败" << std::endl;
            return 1;
        }
        
        server.run();
        
    } catch (const std::exception& e) {
        std::cerr << "异常: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}