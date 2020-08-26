//
// Created by gj on 2019/10/31.
//

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_util.h"
#include "base64.h"

const unsigned char KEY[16] = "EF290D911DD34E8E";
const unsigned char IV[16] = {
        0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15,
        0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D
};

void printBuf(const unsigned char *buf, unsigned int len) {
    printf("buf len :%d\n", len);
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x, ", *(buf + i));
    }
    printf("\n");
}

int main(int argc, char **argv) {
//    unsigned char in[] = {
//            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
//    };
    char* in = "Hello, AES cipher!";

    //orig
    int in_len = sizeof(in);
    printBuf(in, in_len);

    //encrypt
    unsigned int out_len = 0;
    unsigned char *out = encrypt(in, in_len, &out_len, KEY, IV);
    printBuf(out, out_len);

    //base64 encode
    const char *b64_cipher_text = b64_encode(out, out_len);
    printf("base64 result:\t%s\n", b64_cipher_text);

    //base64 decode
    size_t de_size = 0;
    unsigned char *deb64_orig_data = b64_decode_ex(b64_cipher_text, strlen(b64_cipher_text), &de_size);

    //decrypt
    unsigned int out_len2 = 0;
    unsigned char *out_decrypted = decrypt(deb64_orig_data, de_size, &out_len2, KEY, IV);
    printBuf(out_decrypted, out_len2);

    free(out);
    free(b64_cipher_text);
    free(deb64_orig_data);
    free(out_decrypted);

    return EXIT_SUCCESS;
}
