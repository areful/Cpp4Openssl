//
// Created by gj on 8/25/20.
//

#ifndef CPPRSAWITHOPENSSL_CBD_AES_H
#define CPPRSAWITHOPENSSL_CBD_AES_H

#define KEY_SIZE 128

#include <string>

static char KEY_HTTP[17] = "EF290D911DD34E8E";
static char IV_HTTP[17] = {
        0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15,
        0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D, 0
};

static char KEY_PASSWORD[17] = "BuP%y#3!lvq$y^4M";
static char IV_PASSWORD[17] = {
        0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15,
        0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D, 0
};

static char KEY_TRACK[17] = "sgt$%@CVBGgdt12q";
static char IV_TRACK[17] = {
        0x12, 0x34, 0x56, 0x78, 0x90 - 0x100, 0xAB - 0x100, 0xCD - 0x100, 0xEF - 0x100,
        0x12, 0x34, 0x56, 0x78, 0x90 - 0x100, 0xAB - 0x100, 0xCD - 0x100, 0xEF - 0x100, 0
};

std::string encrypt(std::string &content, int type);

std::string decrypt(std::string &content, int type);

#endif //CPPRSAWITHOPENSSL_CBD_AES_H
