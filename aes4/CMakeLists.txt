cmake_minimum_required(VERSION 3.15)

set(VERSION_NUMBER 2)
message("version number: ${VERSION_NUMBER}")

#pkgconfig, openssl
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

aux_source_directory(. AES4_SOURCE)

add_executable(test_aes4
        ${AES4_SOURCE}
        )
target_link_libraries(test_aes4 ${OPENSSL_LIBRARIES})
