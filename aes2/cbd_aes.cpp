//
// Created by gj on 8/25/20.
//

#include "cbd_aes.h"
#include "../b64v2/base64.h"
#include <openssl/aes.h>
#include <string>

using namespace std;

static unsigned char *private_encrypt(unsigned char *input, int in_len, int type);

static char *private_decrypt(unsigned char *in, unsigned int in_len, unsigned int out_len, int type);

string encrypt(string &content, int type) {
    int in_len = content.length();
    auto *out = private_encrypt((unsigned char *) content.c_str(), in_len, type);
    if (out == nullptr) {
        return std::string();
    }

    unsigned int out_len = in_len + (AES_BLOCK_SIZE - in_len % AES_BLOCK_SIZE);
    char *res = b64_encode(out, out_len);
    return std::string(res);
}

static unsigned char *private_encrypt(unsigned char *input, int in_len, int type) {
    AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE + 1] = {0};
    unsigned char iv[AES_BLOCK_SIZE] = {0};

    get_key_iv(key, iv, AES_BLOCK_SIZE, type);
    if (AES_set_encrypt_key(key, KEY_SIZE, &aes) < 0) {
        return nullptr;
    }

    unsigned int out_len = in_len + (AES_BLOCK_SIZE - in_len % AES_BLOCK_SIZE);
    auto *out = (unsigned char *) malloc(out_len);
    AES_cbc_encrypt(input, out, out_len, &aes, iv, AES_ENCRYPT);
    return out;
}

string decrypt(string &content, int type) {
    if (content.empty()) {
        return std::string();
    }

    const char *b64_encrypted_data = content.c_str();
    int in_len = content.length();
    size_t out_len;
    size_t *p_out_len = &out_len;
    auto *in = b64_decode_ex(b64_encrypted_data, in_len, p_out_len);
    char *out = private_decrypt(in, in_len, out_len, type);
    if (out == nullptr) {
        return std::string();
    }
    return string(out);
}

static char *private_decrypt(unsigned char *in, unsigned int in_len, unsigned int out_len, int type) {
    AES_KEY aes;
    int size = AES_BLOCK_SIZE;
    unsigned char key[AES_BLOCK_SIZE + 1] = {0};
    unsigned char iv[AES_BLOCK_SIZE] = {0};

    get_key_iv(key, iv, size, type);
    if (AES_set_decrypt_key(key, KEY_SIZE, &aes) < 0) {
        return nullptr;
    }

    unsigned int total = in_len + (AES_BLOCK_SIZE - in_len % AES_BLOCK_SIZE);
    auto *out = (unsigned char *) malloc(total);
    AES_cbc_encrypt(in, out, total, &aes, iv, AES_DECRYPT);

    unsigned int padding_len = *(out + out_len - 1);
    if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
        out_len -= padding_len;
    }
    char *result = (char *) calloc(out_len + 1, 1);
    strncpy(result, (char *) out, out_len);
    return result;
}