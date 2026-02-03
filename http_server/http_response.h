#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include <time.h>
#include <string>
#include <string.h>

// HTTP响应结构体
typedef struct {
    int status_code;      // 状态码
    std::string headers;  // 响应头
    int headers_len;      // 响应头长度
    std::string body;     // 响应体
    int body_len;         // 响应体长度
} http_response_t;

// 常用MIME类型
#define MIME_HTML "text/html"
#define MIME_JSON "application/json"
#define MIME_TEXT "text/plain"
#define MIME_CSS "text/css"
#define MIME_JS "application/javascript"
#define MIME_PNG "image/png"
#define MIME_JPG "image/jpeg"

// 函数声明
http_response_t* create_http_response(int status, std::string content_type, std::string body, int body_len, bool keep_alive = false);
char* http_response_to_string(http_response_t *res, int *out_len);
void free_http_response(http_response_t *res);
const char* get_status_message(int status_code);

#endif