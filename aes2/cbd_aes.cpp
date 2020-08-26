//
// Created by gj on 8/25/20.
//

#include "cbd_aes.h"
#include "../b64/b64.h"
#include <openssl/aes.h>
#include <cstring>
#include <string>

using namespace std;

static string private_encrypt(string &content, char *key, char *iv);

static string private_decrypt(string &content, char *key, char *iv);

string encrypt(string &content, int type) {
    int size = AES_BLOCK_SIZE + 1;
    char key[17] = {0};
    char iv[17] = {0};
    if (type == 1) {
        strncpy(key, KEY_HTTP, size);
        strncpy(iv, IV_HTTP, size);
    } else if (type == 2) {
        strncpy(key, KEY_PASSWORD, size);
        strncpy(iv, IV_PASSWORD, size);
    } else {
        strncpy(key, KEY_TRACK, size);
        strncpy(iv, IV_TRACK, size);
    }
    return private_encrypt(content, key, iv);
}

static string private_encrypt(string &content, char *key, char *iv) {
    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char *) key, KEY_SIZE, &aes) < 0) {
        return std::string();
    }

    int in_len = content.length();
    unsigned int rest_len = in_len % AES_BLOCK_SIZE;
    unsigned int padding_len = AES_BLOCK_SIZE - rest_len;
    unsigned int out_len = in_len + padding_len;
    char *input = (char *) calloc(1, out_len);
    memcpy(input, content.c_str(), in_len);

    char *out = (char *) malloc(out_len);
    AES_cbc_encrypt((unsigned char *) input, (unsigned char *) out, out_len,
                    &aes,
                    (unsigned char *) iv, AES_ENCRYPT);
    char *res = base64Encode(out, out_len, false);
    return std::string(res);
}

string decrypt(string &content, int type) {
    int size = AES_BLOCK_SIZE + 1;
    char key[17] = {0};
    char iv[17] = {0};
    if (type == 1) {
        strncpy(key, KEY_HTTP, size);
        strncpy(iv, IV_HTTP, size);
    } else if (type == 2) {
        strncpy(key, KEY_PASSWORD, size);
        strncpy(iv, IV_PASSWORD, size);
    } else {
        strncpy(key, KEY_TRACK, size);
        strncpy(iv, IV_TRACK, size);
    }
    return private_decrypt(content, key, iv);
}

static string private_decrypt(string &content, char *key, char *iv) {
    if (content.empty()) {
        return std::string();
    }

    char *b64_encrypted_data = const_cast<char *>(content.c_str());
    int in_len = content.length();
    char *in = base64Decode(b64_encrypted_data, in_len, false);

    AES_KEY aes;
    if (AES_set_decrypt_key((unsigned char *) key, KEY_SIZE, &aes) < 0) {
        return std::string();
    }

    int block_size = (in_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    int total = block_size * AES_BLOCK_SIZE;
    char *out = (char *) malloc(total);
    AES_cbc_encrypt((unsigned char *) in, (unsigned char *) out, total,
                    &aes,
                    (unsigned char *) iv, AES_DECRYPT);

    unsigned int out_len = in_len;
    unsigned int padding_len = (unsigned char) *(out + out_len - 1);
    if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
        out_len -= padding_len;
    }
    char *result = (char *) calloc(out_len + 1, 1);
    strncpy(result, out, out_len);
    return std::string(result);
}