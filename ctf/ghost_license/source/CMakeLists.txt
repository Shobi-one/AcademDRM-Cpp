cmake_minimum_required(VERSION 3.16)
project(GhostLicense LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(GhostLicense
    main.cpp
    license_check.cpp
)

if(MSVC)
    target_compile_options(GhostLicense PRIVATE /W4 /permissive-)
else()
    target_compile_options(GhostLicense PRIVATE -Wall -Wextra -Wpedantic)
endif()
