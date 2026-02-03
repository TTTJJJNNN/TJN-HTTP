#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// HTTP请求结构体
typedef struct {
    char method[16];      // GET, POST等
    char path[256];       // 请求路径
    char version[16];     // HTTP版本
    char headers[1024];   // 请求头（简化处理）
    char body[4096];      // 请求体（简化处理）
    int content_length;   // 内容长度
    int body_len;         // 实际body长度
} http_request_t;

// 函数声明
http_request_t* parse_http_request(const char *data, int len);
void free_http_request(http_request_t *req);
const char* get_header_value(const http_request_t *req, const char *header_name);

#endif