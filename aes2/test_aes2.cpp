#include"test_aes2.h"
#include "../b64/b64.h"
#include "cbd_aes.h"

#include <cstdio>
#include <cstdlib>
#include <openssl/aes.h>
#include <cstring>
#include <string>
#include <iostream>

using namespace std;

void test_encrypt() {
    char *encrypt_string;
    AES_KEY aes;
    char key[17] = "EF290D911DD34E8E";
    char iv[17] = {
            0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15, 0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D};
    std::string input_string = "helloworldhellow";
    int nLen = input_string.length();
    int nBei = nLen / AES_BLOCK_SIZE + 1;
    int nTotal = nBei * AES_BLOCK_SIZE;
    char *enc_s = (char *) calloc(nTotal + 1, 1);
    int nNumber;
    if (nLen % 16 > 0)
        nNumber = nTotal - nLen;
    else
        nNumber = 16;
    memset(enc_s, nNumber, nTotal);
    memcpy(enc_s, input_string.data(), nLen);
    if (AES_set_encrypt_key((unsigned char *) key, 128, &aes) < 0) {
        exit(-1);
    }
    encrypt_string = (char *) malloc(nTotal);
    AES_cbc_encrypt((unsigned char *) enc_s, (unsigned char *) encrypt_string, nBei * 16,
                    &aes,
                    (unsigned char *) iv, AES_ENCRYPT);
    char *res = base64Encode(encrypt_string, nBei * 16, false);
    printf("the encrypt result is %s\n", res);
}

void test_decrypt() {
    char *encrypt_array;
    AES_KEY aes;
    char key[17] = "EF290D911DD34E8E";
    char iv[17] = {
            0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15, 0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D};
    char *tmp = "H0apsWs7g2Hw7G48g9FKWg==";
    char *decode = base64Decode(tmp, strlen(tmp), false);
    if (AES_set_decrypt_key((unsigned char *) key, 128, &aes) < 0) {
        exit(-1);
    }
    encrypt_array = (char *) malloc(strlen(tmp));
    AES_cbc_encrypt((unsigned char *) decode, (unsigned char *) encrypt_array, strlen(decode),
                    &aes,
                    (unsigned char *) iv, AES_DECRYPT);
    int len = strlen(encrypt_array);
    int k = len;
    for (int i = 0; i < len; i++) {
        if ((int) (encrypt_array[i]) <= 16) {
            k = i;
            break;
        }
    }
    char *result = (char *) calloc(k + 1, 1);
    strncpy(result, encrypt_array, k);
    printf("the decrypt result is %s\n", result);
}

int main() {
    test_encrypt();
    test_decrypt();

    string content = "Hello, AES cipher!第一部分";
    string encrypted = encrypt(content, 1);
    cout << encrypted << endl;

    string decrypted = decrypt(encrypted, 1);
    cout << decrypted << endl;

    return 0;
}
