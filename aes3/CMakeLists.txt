cmake_minimum_required(VERSION 3.15)

set(VERSION_NUMBER 2)
message("version number: ${VERSION_NUMBER}")

#aux_source_directory(. AES3_SOURCE)
#add_library(cbc SHARED ${AES3_SOURCE})

add_executable(test_aes3
        aes_util_test.c
        aes.c
        aes.h
        aes_util.c
        aes_util.h
        base64.c
        base64.h
        )
