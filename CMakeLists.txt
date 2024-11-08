cmake_minimum_required(VERSION 3.29)
project(inotify_monitor C)

set(CMAKE_C_STANDARD 11)

add_executable(inotify_monitor main.c
        proc.c
        headers.h
        events.c)
