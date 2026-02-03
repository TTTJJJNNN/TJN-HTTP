#include "http_response.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <cstring>

// 状态码描述
const char* get_status_message(int status_code) {
    switch(status_code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default: return "Unknown";
    }
}

// 创建HTTP响应 改动
http_response_t* create_http_response(int status, std::string content_type, std::string body, int body_len, bool keep_alive) {
    // 构建响应结构体
    http_response_t* res = new http_response_t;
    
    // 构建状态码
    res->status_code = status;
    
    // 构建响应头
    std::string headers = "";
    headers += "HTTP/1.1 " + std::to_string(status) + " " + get_status_message(status) + "\r\n";
    headers += "Content-Type: " + content_type + "\r\n";
    headers += "Content-Length: " + std::to_string(body_len) + "\r\n";
    if (keep_alive) headers += "Connection: keep-alive\r\n";
    headers += "\r\n";
    res->headers = headers;
    res->headers_len = headers.size();
    
    // 构建响应体
    if (body_len > 0) {
        res->body = body;
        res->body_len = body_len;
    } else {
        res->body = "";
        res->body_len = 0;
    }
    
    return res;
}

// 将响应转换为字符串
char* http_response_to_string(http_response_t *res, int *out_len) {
    int total_len = res->headers_len + res->body_len;
    *out_len = total_len;
    
    // 直接拼接（C++方式）
    std::string combined = res->headers + res->body;
    
    // 分配内存并复制
    char* c_str = new char[combined.length() + 1];  // +1 for '\0'
    std::strcpy(c_str, combined.c_str());  // 自动复制
    
    return c_str;  // 返回指针
}

// 释放响应结构体
void free_http_response(http_response_t* res) {
    if (res) {
        delete res;  // std::string会自动析构
    }
}