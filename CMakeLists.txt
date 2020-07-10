#
# Created by areful on 2020/07/09/.
#

cmake_minimum_required(VERSION 3.16)
project(CppRSAWithOpenssl)

set(CMAKE_CXX_STANDARD 14)

find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else ()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif ()

add_executable(Cpp4Openssl
        main.cpp
        b64/b64.cpp
        b64/b64.h
        b64/test_b64.cpp
        b64/test_b64.h
        rsa/rsa.cpp
        rsa/rsa.h
        rsa/test_rsa.cpp
        rsa/test_rsa.h
        aes/test_aes.cpp
        aes/test_aes.h)
target_link_libraries(Cpp4Openssl ${OPENSSL_LIBRARIES})