//
// Created by gj on 8/25/20.
//

#include "cbd_aes.h"
#include "../b64/b64.h"

#include <cstdio>
#include <cstdlib>
#include <openssl/aes.h>
#include <cstring>
#include <string>

static string private_encrypt(string &content, char *key, char *iv);

static string private_decrypt(string &content, char *key, char *iv);

string encrypt(string &content, int type) {
    char key_http[17] = "EF290D911DD34E8E";
    char iv_http[17] = {
            0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15, 0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D, 0};

    char key_password[17] = "EF290D911DD34E8E";
    char iv_password[17] = {
            0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15, 0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D, 0};

    char key_track[17] = "EF290D911DD34E8E";
    char iv_track[17] = {
            0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15, 0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D, 0};

    char *key, *iv;
    if (type == 1) {
        key = key_http;
        iv = iv_http;
    } else if (type == 2) {
        key = key_password;
        iv = iv_password;
    } else {
        key = key_track;
        iv = iv_track;
    }
    return private_encrypt(content, key, iv);
}

static string private_encrypt(string &content, char *key, char *iv) {
    char *out;
    AES_KEY aes;
    int len = content.length();
    int block_size = len / AES_BLOCK_SIZE + 1;
    int total = block_size * AES_BLOCK_SIZE;
    char *enc_s = (char *) calloc(total + 1, 1);
    int nNumber;
    if (len % 16 > 0)
        nNumber = total - len;
    else
        nNumber = 16;
    memset(enc_s, nNumber, total);
    strncpy(enc_s, content.data(), len);
    if (AES_set_encrypt_key((unsigned char *) key, 128, &aes) < 0) {
        return std::string();
    }

    out = (char *) malloc(total);
    AES_cbc_encrypt((unsigned char *) enc_s, (unsigned char *) out, block_size * 16,
                    &aes,
                    (unsigned char *) iv, AES_ENCRYPT);
    char *res = base64Encode(out, block_size * 16, false);
    printf("encrypted: %s\n", res);
    return std::string(res);
}

string decrypt(string &content, int type) {
    char key_http[17] = "EF290D911DD34E8E";
    char iv_http[17] = {
            0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15, 0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D, 0};

    char key_password[17] = "EF290D911DD34E8E";
    char iv_password[17] = {
            0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15, 0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D, 0};

    char key_track[17] = "EF290D911DD34E8E";
    char iv_track[17] = {
            0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15, 0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D, 0};

    char *key, *iv;
    if (type == 1) {
        key = key_http;
        iv = iv_http;
    } else if (type == 2) {
        key = key_password;
        iv = iv_password;
    } else {
        key = key_track;
        iv = iv_track;
    }
    return private_decrypt(content, key, iv);
}

static string private_decrypt(string &content, char *key, char *iv) {
    if (content.empty()) {
        return std::string();
    }

    char *b64_encrypted_data = const_cast<char *>(content.data());
    char *in = base64Decode(b64_encrypted_data, strlen(b64_encrypted_data), false);

    AES_KEY aes;
    if (AES_set_decrypt_key((unsigned char *) key, 128, &aes) < 0) {
        return std::string();
    }

    char *out = (char *) malloc(strlen(b64_encrypted_data));
    AES_cbc_encrypt((unsigned char *) in, (unsigned char *) out, strlen(in),
                    &aes,
                    (unsigned char *) iv, AES_DECRYPT);
    int len = strlen(out);
    int k = len;
    for (int i = 0; i < len; i++) {
        if ((int) (out[i]) <= 16) {
            k = i;
            break;
        }
    }
    char *result = (char *) calloc(k + 1, 1);
    strncpy(result, out, k);
    printf("decrypted: %s\n", result);
    return std::string(result);
}
