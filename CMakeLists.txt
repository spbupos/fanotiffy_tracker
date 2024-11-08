cmake_minimum_required(VERSION 3.29)
project(inotify_monitor CXX)

set(CMAKE_CXX_STANDARD 20)

add_executable(inotify_monitor main.cpp
        headers.h
        events.cpp)
