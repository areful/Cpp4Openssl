//
// Created by gj on 8/25/20.
//

#include "cbd_aes.h"
#include "../b64/b64.h"
#include <openssl/aes.h>
#include <cstring>
#include <string>

using namespace std;

static string private_encrypt(string &content, unsigned char *key, unsigned char *iv);

static string private_decrypt(string &content, unsigned char *key, unsigned char *iv);

string encrypt(string &content, int type) {
    int size = AES_BLOCK_SIZE;
    unsigned char key[AES_BLOCK_SIZE + 1] = {0};
    unsigned char iv[AES_BLOCK_SIZE] = {0};
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
    return private_encrypt(content, key, iv);
}

static string private_encrypt(string &content, unsigned char *key, unsigned char *iv) {
    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char *) key, KEY_SIZE, &aes) < 0) {
        return std::string();
    }

    int in_len = content.length();
    unsigned int rest_len = in_len % AES_BLOCK_SIZE;
    unsigned int padding_len = AES_BLOCK_SIZE - rest_len;
    unsigned int out_len = in_len + padding_len;
    auto *input = (unsigned char *) calloc(1, out_len);
    memcpy(input, content.c_str(), in_len);

    auto *out = (unsigned char *) malloc(out_len);
    AES_cbc_encrypt(input, out, out_len, &aes, iv, AES_ENCRYPT);
    char *res = base64Encode(reinterpret_cast<const char *>(out), out_len, false);
    return std::string(res);
}

string decrypt(string &content, int type) {
    int size = AES_BLOCK_SIZE;
    unsigned char key[AES_BLOCK_SIZE + 1] = {0};
    unsigned char iv[AES_BLOCK_SIZE] = {0};
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
    return private_decrypt(content, key, iv);
}

static string private_decrypt(string &content, unsigned char *key, unsigned char *iv) {
    if (content.empty()) {
        return std::string();
    }

    char *b64_encrypted_data = const_cast<char *>(content.c_str());
    int in_len = content.length();
    auto *in = reinterpret_cast<unsigned char *>(base64Decode(b64_encrypted_data, in_len, false));

    AES_KEY aes;
    if (AES_set_decrypt_key(key, KEY_SIZE, &aes) < 0) {
        return std::string();
    }

    int block_size = (in_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    int total = block_size * AES_BLOCK_SIZE;
    auto *out = (unsigned char *) malloc(total);
    AES_cbc_encrypt(in, out, total, &aes, iv, AES_DECRYPT);

    unsigned int out_len = in_len;
    unsigned int padding_len = *(out + out_len - 1);
    if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
        out_len -= padding_len;
    }
    char *result = (char *) calloc(out_len + 1, 1);
    strncpy(result, (char *) out, out_len);
    return std::string(result);
}