cmake_minimum_required(VERSION 3.22.1)
project("novacore")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Собираем обе программы в одну библиотеку
add_library(novacore SHARED 
    nova_scanner.cpp
    native_core.cpp
)

target_compile_options(novacore PRIVATE -O3 -ffast-math -Wall)

find_library(log-lib log)
target_link_libraries(novacore ${log-lib})
