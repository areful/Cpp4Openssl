//
// Created by gj on 8/26/2020.
//
#include "cbd_aes5.h"
#include "b64.h"
#include <iostream>

using namespace std;

int main() {
    unsigned char KEY_HTTP[AES_BLOCK_SIZE + 1] = "EF290D911DD34E8E";
    unsigned char IV_HTTP[AES_BLOCK_SIZE] = {
            0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15,
            0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D
    };

    auto *aes = new CbdAes();
    aes->setAesKey(KEY_HTTP, 16);
    aes->setAesIv(IV_HTTP, 16);

    // encrypt aes
    string msg = string("hello,world!2. 点击切换tab的展示的主页面不展示返回icon；当进入下一级页面的时候，在页面的右下位置增加一个返回icon；");
    const auto *in = reinterpret_cast<const unsigned char *>(msg.c_str());
    size_t in_len = msg.size() + 1;
    unsigned char *encrypted = nullptr;
    int encrypted_len = aes->aesEncrypt(in, in_len, &encrypted);
    if (encrypted_len == FAILURE) {
        fprintf(stderr, "Encryption failed\n");
        return FAILURE;
    }

//    // decrypt aes
//    unsigned char *decrypted = nullptr;
//    int decrypted_len = aes->aesDecrypt(encrypted, encrypted_len, (unsigned char **) &decrypted);
//    if (decrypted_len == FAILURE) {
//        fprintf(stderr, "Decryption failed\n");
//        return FAILURE;
//    }

    // encode base64
    char *b64_encoded = base64Encode(encrypted, encrypted_len);
    printf("Encrypted message: %s\n", b64_encoded);

    // decode base64
    unsigned char *b64_decoded = nullptr;
    int b64_decode_len = base64Decode(b64_encoded, strlen(b64_encoded), &b64_decoded);

    // decrypt aes
    unsigned char *decrypted = nullptr;
    int decrypted_len = aes->aesDecrypt(b64_decoded, b64_decode_len, (unsigned char **) &decrypted);
    if (decrypted_len == FAILURE) {
        fprintf(stderr, "Decryption failed\n");
        return FAILURE;
    }

    printf("Decrypted message: %s\n", decrypted);

    free(b64_encoded);
    free(b64_decoded);
    free(encrypted);
    free(decrypted);
}