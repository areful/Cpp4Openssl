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

    char *b64_encrypted_data = const_cast<char *>(content.data());
    int in_len = content.length();
    char *in = base64Decode(b64_encrypted_data, in_len, false);

    AES_KEY aes;
    if (AES_set_decrypt_key((unsigned char *) key, 128, &aes) < 0) {
        return std::string();
    }

    int len = content.length();
    int block_size = len / AES_BLOCK_SIZE + 1;
    int total = block_size * AES_BLOCK_SIZE;

    char *out = (char *) malloc(total);
    AES_cbc_encrypt((unsigned char *) in, (unsigned char *) out, total,
                    &aes,
                    (unsigned char *) iv, AES_DECRYPT);
    int out_len = total;
    int k = out_len;
    for (int i = 0; i < out_len; i++) {
        if ((int) (out[i]) <= 16) {
            k = i;
            break;
        }
    }
    char *result = (char *) calloc(k + 1, 1);
    strncpy(result, out, k);
    return std::string(result);
}