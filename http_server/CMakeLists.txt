# http_server/CMakeLists.txt

# 创建HTTP静态库
add_library(http_lib STATIC
    http_request.cpp
    http_response.cpp
    router.cpp
)

# 关键修改：使用PUBLIC或INTERFACE，并包含上层目录
target_include_directories(http_lib 
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)

# 或者更简单：直接设置包含目录
# target_include_directories(http_lib PUBLIC
#     ${CMAKE_CURRENT_SOURCE_DIR}
# )

# 添加编译选项
target_compile_options(http_lib PRIVATE
    -Wall
    -Wextra
    -O2
)

# 可选：设置C++标准
set_target_properties(http_lib PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
)