cmake_minimum_required(VERSION 4.0)
project(messenger)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_SRC Platform/linux_platform.cpp)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(PLATFORM_SRC Platform/windows_platform.cpp)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(PLATFORM_SRC Platform/mac_platform.cpp
            core/Task.h
            core/TaskQueue.cpp
            core/TaskQueue.h)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

add_library(messenger SHARED ${PLATFORM_SRC})

target_link_libraries(messenger PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(messenger_test main.cpp)

target_link_libraries(messenger_test PRIVATE messenger OpenSSL::SSL OpenSSL::Crypto)
