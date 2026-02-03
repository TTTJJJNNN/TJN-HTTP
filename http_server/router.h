#ifndef ROUTER_H
#define ROUTER_H

#include "http_request.h"
#include "http_response.h"
#include <string>

// 路由处理函数类型
typedef http_response_t* (*route_handler_t)(http_request_t *req, bool keep_alive);

// 路由表项
typedef struct {
    const char *method;   // 请求方法
    const char *path;     // 请求路径
    route_handler_t handler; // 处理函数
} route_entry_t;

// 默认路由处理函数
http_response_t* handle_root(http_request_t *req, bool keep_alive);
http_response_t* handle_echo(http_request_t *req, bool keep_alive);
http_response_t* handle_api(http_request_t *req, bool keep_alive);
http_response_t* handle_not_found(http_request_t *req, bool keep_alive);
http_response_t* handle_method_not_allowed(http_request_t *req, bool keep_alive);
// 路由分发函数
http_response_t* route_request(http_request_t *req);

#endif