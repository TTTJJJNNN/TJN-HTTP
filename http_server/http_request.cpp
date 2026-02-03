#include "http_request.h"
#include <ctype.h>

// 解析HTTP请求
http_request_t* parse_http_request(const char *data, int len) {
    if (!data || len <= 0) return NULL;
    
    http_request_t *req = (http_request_t*)calloc(1, sizeof(http_request_t));
    if (!req) return NULL;
    
    char *buffer = (char*)malloc(len + 1);
    if (!buffer) {
        free(req);
        return NULL;
    }
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    
    // 解析请求行 (第一行)
    char *line = strtok(buffer, "\r\n");
    if (!line) {
        free(buffer);
        free(req);
        return NULL;
    }
    
    // 解析方法、路径、版本
    sscanf(line, "%15s %255s %15s", req->method, req->path, req->version);
    
    // 解析头部
    char *headers_start = strtok(NULL, "\0");
    if (headers_start) {
        // 找到头部结束位置（空行）
        char *body_start = strstr(headers_start, "\r\n\r\n");
        if (body_start) {
            *body_start = '\0';  // 分割头部和body
            body_start += 4;     // 跳过 "\r\n\r\n"
            
            // 复制头部
            int header_len = body_start - headers_start - 4;
            if (header_len > 0 && header_len < 1024) {
                strncpy(req->headers, headers_start, header_len);
                req->headers[header_len] = '\0';
            }
            
            // 解析Content-Length
            char *cl = strstr(req->headers, "Content-Length:");
            if (cl) {
                sscanf(cl + 15, "%d", &req->content_length);
            }
            
            // 解析body
            if (body_start && req->content_length > 0) {
                int body_size = len - (body_start - buffer);
                if (body_size > 0) {
                    int copy_len = body_size < 4096 ? body_size : 4095;
                    strncpy(req->body, body_start, copy_len);
                    req->body[copy_len] = '\0';
                    req->body_len = strlen(req->body);
                }
            }
        }
    }
    
    free(buffer);
    return req;
}

// 释放请求结构体
void free_http_request(http_request_t *req) {
    if (req) {
        free(req);
    }
}

// 获取头部值（简化版本）
const char* get_header_value(const http_request_t *req, const char *header_name) {
    if (!req || !header_name) return NULL;
    
    char search_str[256];
    snprintf(search_str, sizeof(search_str), "%s:", header_name);
    
    const char *pos = strstr(req->headers, search_str);
    if (!pos) return NULL;
    
    pos += strlen(search_str);
    // 跳过空格
    while (*pos && isspace(*pos)) pos++;
    
    // 找到值的结束位置
    const char *end = strchr(pos, '\r');
    if (!end) return NULL;
    
    // 临时返回位置（注意：这不是线程安全的，仅用于示例）
    static char value[256];
    int len = end - pos;
    if (len >= 256) len = 255;
    strncpy(value, pos, len);
    value[len] = '\0';
    
    return value;
}