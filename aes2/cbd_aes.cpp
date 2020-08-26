//
// Created by gj on 8/25/20.
//

#include "cbd_aes.h"
#include "../b64v2/base64.h"
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
    unsigned int out_len = in_len + (AES_BLOCK_SIZE - in_len % AES_BLOCK_SIZE);

    auto *input = (unsigned char *) calloc(1, out_len + 1);
    strncpy((char *) input, content.c_str(), in_len);

    auto *out = (unsigned char *) malloc(out_len);
    AES_cbc_encrypt(input, out, out_len, &aes, iv, AES_ENCRYPT);
    char *res = b64_encode(out, out_len);
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

    size_t out_len;
    size_t *p_out_len = &out_len;
    auto *in = b64_decode_ex(b64_encrypted_data, in_len, reinterpret_cast<size_t *>(p_out_len));

    AES_KEY aes;
    if (AES_set_decrypt_key(key, KEY_SIZE, &aes) < 0) {
        return std::string();
    }

    int total = in_len + (AES_BLOCK_SIZE - in_len % AES_BLOCK_SIZE);
    auto *out = (unsigned char *) malloc(total);
    AES_cbc_encrypt(in, out, total, &aes, iv, AES_DECRYPT);

    unsigned int padding_len = *(out + out_len - 1);
    if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
        out_len -= padding_len;
    }
    char *result = (char *) calloc(out_len + 1, 1);
    strncpy(result, (char *) out, out_len);
    return std::string(result);
}