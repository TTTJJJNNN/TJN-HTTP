#include <iostream>
#include <string>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

const int PORT = 8888;
const int BUFFER_SIZE = 1024;

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0); // 创建socket

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));

    listen(server_fd, 3);

    std::cout << "服务器启动，等待客户端连接..." << std::endl;


    sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);

    std::cout << "客户端已连接" << std::endl;


    char buffer[BUFFER_SIZE];
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);

        int bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0);

        std::cout << "收到客户端消息: " << buffer << std::endl;

        if (strcmp(buffer, "exit") == 0) {
            std::cout << "客户端请求退出" << std::endl;
            break;
        }

        std::cout << "请输入回复: ";
        std::string reply;
        std::getline(std::cin, reply);
        
        send(client_fd, reply.c_str(), reply.length(), 0);
    }

    close(client_fd);
    close(server_fd);
    std::cout << "服务器已关闭" << std::endl;

    return 0;
}