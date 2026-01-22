#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

const int PORT = 8888;
const char* SERVER_IP = "127.0.0.1"; // 本地回环地址
const int BUFFER_SIZE = 1024;

int main() {
    // 创建socket
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == -1) {
        std::cerr << "Socket创建失败" << std::endl;
        return -1;
    }

    // 设置服务器地址
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    // 转换IP地址
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        std::cerr << "无效地址/地址不支持" << std::endl;
        return -1;
    }

    // 连接服务器
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "连接失败" << std::endl;
        return -1;
    }

    std::cout << "已连接到服务器 " << SERVER_IP << ":" << PORT << std::endl;

    // 通信循环
    char buffer[BUFFER_SIZE];
    while (true) {
        // 发送消息
        std::cout << "请输入消息 (输入'exit'退出): ";
        std::string message;
        std::getline(std::cin, message);

        if (send(client_fd, message.c_str(), message.length(), 0) < 0) {
            std::cerr << "发送失败" << std::endl;
            break;
        }

        // 检查是否退出
        if (message == "exit") {
            std::cout << "退出程序" << std::endl;
            break;
        }

        // 接收服务器回复
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            std::cerr << "服务器断开连接" << std::endl;
            break;
        }

        std::cout << "服务器回复: " << buffer << std::endl;
    }

    // 关闭socket
    close(client_fd);
    std::cout << "客户端已关闭" << std::endl;

    return 0;
}