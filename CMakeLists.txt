cmake_minimum_required(VERSION 3.22.1)
project("novascanner")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(novascanner SHARED nova_scanner.cpp)
target_compile_options(novascanner PRIVATE -O3 -ffast-math -Wall)

find_library(log-lib log)
target_link_libraries(novascanner ${log-lib})
