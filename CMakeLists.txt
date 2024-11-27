cmake_minimum_required(VERSION 3.12)
project(while_lang VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

add_executable(while_lang src/main.cpp src/lexer.cpp src/ast.cpp src/codegen.cpp)
target_include_directories(while_lang PRIVATE src)
target_include_directories(while_lang PRIVATE include)

llvm_map_components_to_libnames(llvm_libs core orcjit native all)

target_link_libraries(while_lang ${llvm_libs})

