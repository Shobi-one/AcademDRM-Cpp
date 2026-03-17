cmake_minimum_required(VERSION 3.20)

project(AcademDRMClient LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to a local vcpkg toolchain if the caller did not provide one.
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(_local_vcpkg_toolchain "${CMAKE_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")
    if(EXISTS "${_local_vcpkg_toolchain}")
        set(CMAKE_TOOLCHAIN_FILE "${_local_vcpkg_toolchain}" CACHE STRING "vcpkg toolchain file")
    endif()
endif()

if(NOT DEFINED VCPKG_TARGET_TRIPLET)
    set(VCPKG_TARGET_TRIPLET "x64-windows" CACHE STRING "vcpkg target triplet")
endif()

find_package(CURL CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(AcademDRMClient
    client/src/main.cpp
    client/src/license_client.cpp
    client/src/crypto_verify.cpp
    client/src/hardware_id.cpp
    client/protected/donut_animation.cpp
)

target_include_directories(AcademDRMClient PRIVATE client/include)

target_link_libraries(AcademDRMClient PRIVATE
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

if(WIN32)
    if(DEFINED VCPKG_INSTALLED_DIR)
        set(_vcpkg_bin_dir "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin")
    else()
        set(_vcpkg_bin_dir "${CMAKE_SOURCE_DIR}/vcpkg/installed/${VCPKG_TARGET_TRIPLET}/bin")
    endif()

    set(_runtime_dlls
        libcurl.dll
        libcrypto-3-x64.dll
        libssl-3-x64.dll
        zlib1.dll
    )

    foreach(_dll IN LISTS _runtime_dlls)
        add_custom_command(TARGET AcademDRMClient POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_vcpkg_bin_dir}/${_dll}"
                "$<TARGET_FILE_DIR:AcademDRMClient>/${_dll}"
            VERBATIM
        )
    endforeach()
endif()
