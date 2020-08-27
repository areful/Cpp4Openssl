#
# Created by areful on 2020/07/09/.
#

cmake_minimum_required(VERSION 3.16)
project(CppRSAWithOpenssl)

set(CMAKE_CXX_STANDARD 14)

#pkgconfig, openssl
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else ()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif ()

# sub module files
aux_source_directory(aes AES_FILES)
aux_source_directory(rsa RSA_FILES)
aux_source_directory(b64 BASE64_FILES)
aux_source_directory(b64v2 BASE64_FILES_V2)

# application
add_executable(Cpp4Openssl
        main.cpp
        ${AES_FILES}
        ${RSA_FILES}
        ${BASE64_FILES})
target_link_libraries(Cpp4Openssl ${OPENSSL_LIBRARIES})

aux_source_directory(aes2 AES2_SOURCE)
add_executable(test_aes2
        ${AES2_SOURCE}
        ${BASE64_FILES_V2}
        )
target_link_libraries(test_aes2 ${OPENSSL_LIBRARIES})

add_subdirectory(aes3)

add_subdirectory(aes4)

add_subdirectory(aes5)