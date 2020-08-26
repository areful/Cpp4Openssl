//
// Created by gj on 8/25/20.
//

#ifndef CPPRSAWITHOPENSSL_CBD_AES_H
#define CPPRSAWITHOPENSSL_CBD_AES_H

#define KEY_SIZE 128

#include <string>
#include <openssl/aes.h>
#include <cstring>

static unsigned char KEY_HTTP[AES_BLOCK_SIZE + 1] = "EF290D911DD34E8E";
static unsigned char IV_HTTP[AES_BLOCK_SIZE] = {
        0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15,
        0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D
};

static unsigned char KEY_PASSWORD[AES_BLOCK_SIZE + 1] = "BuP%y#3!lvq$y^4M";
static unsigned char IV_PASSWORD[AES_BLOCK_SIZE] = {
        0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15,
        0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D
};

static unsigned char KEY_TRACK[AES_BLOCK_SIZE + 1] = "sgt$%@CVBGgdt12q";
static unsigned char IV_TRACK[AES_BLOCK_SIZE] = {
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
};

static void get_key_iv(unsigned char *key, unsigned char *iv, int size, int type) {
    if (type == 1) {
        memcpy(key, KEY_HTTP, size);
        memcpy(iv, IV_HTTP, size);
    } else if (type == 2) {
        memcpy(key, KEY_PASSWORD, size);
        memcpy(iv, IV_PASSWORD, size);
    } else {
        memcpy(key, KEY_TRACK, size);
        memcpy(iv, IV_TRACK, size);
    }
}

std::string encrypt(std::string &content, int type);

std::string decrypt(std::string &content, int type);

#endif //CPPRSAWITHOPENSSL_CBD_AES_H
