cmake_minimum_required(VERSION 3.10)
project(tjn_http_server VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加HTTP库子目录
add_subdirectory(http_server)

# 添加主可执行文件
add_executable(${PROJECT_NAME} Epoll_server.cpp)

# 链接HTTP库
target_link_libraries(${PROJECT_NAME} PRIVATE http_lib)

# 包含头文件路径
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/http_server
)

# 链接线程库
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)

# 编译选项
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -O2
    -pthread
)