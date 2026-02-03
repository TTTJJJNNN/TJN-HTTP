#include "router.h"
#include <stdio.h>
#include <string.h>

// 路由表
static route_entry_t routes[] = {
    {"GET", "/", handle_root},
    {"GET", "/echo", handle_echo},
    {"GET", "/api/status", handle_api},
    {NULL, NULL, NULL}  // 结束标记
};

// 处理根路径 改动
http_response_t* handle_root(http_request_t *req, bool keep_alive) {
    (void)req; // 避免未使用参数警告
    
    // 最简单的HTML响应体
    std::string html = "<h1>Hello from Server</h1>";
    
    // 创建响应
    return create_http_response(200, "text/html", html, html.length(), keep_alive);
}

// 处理回显请求
http_response_t* handle_echo(http_request_t *req, bool keep_alive) {
    // 从查询参数获取text
    char *query = strstr(req->path, "?text=");
    if (query) {
        char text[256];
        strncpy(text, query + 6, 255);
        text[255] = '\0';
        
        // 简单的HTML响应
        char response[512];
        snprintf(response, sizeof(response),
            "<html><body>"
            "<h1>Echo</h1>"
            "<p>You said: <strong>%s</strong></p>"
            "<a href='/'>Back to home</a>"
            "</body></html>",
            text);
        
        return create_http_response(200, MIME_HTML, response, strlen(response), keep_alive);
    }
    
    // 没有text参数
    const char *response = 
        "<html><body>"
        "<h1>Echo Endpoint</h1>"
        "<p>Usage: /echo?text=your_message</p>"
        "<a href='/'>Back to home</a>"
        "</body></html>";
    
    return create_http_response(200, MIME_HTML, response, strlen(response), keep_alive);
}

// 处理API请求
http_response_t* handle_api(http_request_t *req, bool keep_alive) {
    const char *json = 
        "{\n"
        "  \"server\": \"simple-epoll-http\",\n"
        "  \"version\": \"1.0\",\n"
        "  \"status\": \"running\",\n"
        "  \"timestamp\": %ld,\n"
        "  \"features\": [\"GET\", \"static files\", \"API\"]\n"
        "}";
    
    char response[512];
    snprintf(response, sizeof(response), json, time(NULL));
    
    return create_http_response(200, MIME_JSON, response, strlen(response), keep_alive);
}

// 404处理
http_response_t* handle_not_found(http_request_t *req, bool keep_alive) {
    char response[512];
    snprintf(response, sizeof(response),
        "<html><body>"
        "<h1>404 Not Found</h1>"
        "<p>The requested path <code>%s</code> was not found on this server.</p>"
        "<a href='/'>Back to home</a>"
        "</body></html>",
        req->path);
    
    return create_http_response(404, MIME_HTML, response, strlen(response), keep_alive);
}

// 405处理
http_response_t* handle_method_not_allowed(http_request_t *req, bool keep_alive) {
    char response[512];
    snprintf(response, sizeof(response),
        "<html><body>"
        "<h1>405 Method Not Allowed</h1>"
        "<p>The method <code>%s</code> is not allowed for this resource.</p>"
        "<a href='/'>Back to home</a>"
        "</body></html>",
        req->method);
    
    return create_http_response(405, MIME_HTML, response, strlen(response), keep_alive);
}

// 路由分发
http_response_t* route_request(http_request_t *req) {
    bool keep_alive = true;
    if (!req) {
        return create_http_response(400, MIME_TEXT, "Bad Request", 12, keep_alive);
    }
    
    // 检查请求方法是否支持
    if (strcmp(req->method, "GET") != 0 && strcmp(req->method, "POST") != 0) {
        return handle_method_not_allowed(req, keep_alive);
    }
    
    // 遍历路由表
    for (int i = 0; routes[i].method != NULL; i++) {
        if (strcmp(req->method, routes[i].method) == 0) {
            // 检查路径匹配
            if (strcmp(req->path, routes[i].path) == 0) {
                return routes[i].handler(req, keep_alive);
            }

            // 可添加支持简单的前缀匹配（如/static/）
        }
    }
    
    // 没有找到匹配的路由
    return handle_not_found(req, keep_alive);
}