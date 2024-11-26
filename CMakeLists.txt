cmake_minimum_required(VERSION 3.12)
project(while_lang VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(while_lang src/main.cpp src/lexer.cpp src/ast.cpp)

target_include_directories(while_lang PRIVATE src)
target_include_directories(while_lang PRIVATE include)
