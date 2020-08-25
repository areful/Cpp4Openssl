/*
// Created by areful on 2020/07/10/.
// thanks to: https://blog.csdn.net/alan00000/article/details/44241865#
*/

#include <cstdio>
#include <cstdlib>
#include <openssl/aes.h>
#include <cstring>

void test_aes() {
    AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16
    unsigned char iv[AES_BLOCK_SIZE];        // init vector
    unsigned char *input_string;
    unsigned char *encrypt_string;
    unsigned char *decrypt_string;
    unsigned int len;        // encrypt length (in multiple of AES_BLOCK_SIZE)
    unsigned int i;
    const char *msg = "Hello, AES cipher!";
    len = strlen(msg);

    input_string = (unsigned char *) calloc(len, sizeof(unsigned char));
    if (input_string == nullptr) {
        fprintf(stderr, "Unable to allocate memory for input_string\n");
        exit(-1);
    }
    strncpy((char *) input_string, msg, len);

    // Generate AES 128-bit key
    for (i = 0; i < 16; ++i) {
        key[i] = 32 + i;
    }

    // Set encryption key
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set encryption key in AES\n");
        exit(-1);
    }

    // alloc encrypt_string
    encrypt_string = (unsigned char *) calloc(len, sizeof(unsigned char));
    if (encrypt_string == nullptr) {
        fprintf(stderr, "Unable to allocate memory for encrypt_string\n");
        exit(-1);
    }

    // encrypt (iv will change)
    AES_cbc_encrypt(input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);

    // alloc decrypt_string
    decrypt_string = (unsigned char *) calloc(len, sizeof(unsigned char));
    if (decrypt_string == nullptr) {
        fprintf(stderr, "Unable to allocate memory for decrypt_string\n");
        exit(-1);
    }

    // Set decryption key
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_decrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set decryption key in AES\n");
        exit(-1);
    }

    // decrypt
    AES_cbc_encrypt(encrypt_string, decrypt_string, len, &aes, iv, AES_DECRYPT);

    // print
    printf("input_string = %s\n", input_string);
    printf("encrypted string = ");
    for (i = 0; i < len; ++i) {
        printf("%x%x", (encrypt_string[i] >> 4) & 0xf, encrypt_string[i] & 0xf);
    }
    printf("\n");
    printf("decrypted string = %s\n", decrypt_string);

    free(input_string);
    free(decrypt_string);
}