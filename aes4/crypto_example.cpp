#include "crypto_example.h"
#include "../aes5/cbd_aes5.h"

using std::string;
using std::cin;

int main() {
    Crypto crypto;

#ifdef PRINT_KEYS
    printKeys(&crypto);
#endif

    unsigned char KEY_HTTP[AES_BLOCK_SIZE + 1] = "EF290D911DD34E8E";
    unsigned char IV_HTTP[AES_BLOCK_SIZE] = {
            0x13, 0x33, 0x5D, 0x7F, 0x52, 0x29, 0x2C, 0x15,
            0x3B, 0x51, 0x55, 0x23, 0x4F, 0x19, 0x36, 0x3D
    };
    crypto.setAesKey(KEY_HTTP, 16);
    crypto.setAesIv(IV_HTTP, 16);
    unsigned char *publicKey = (unsigned char *) "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtbplTenxG+rOhCgzVwdTLKt2BEooYk347sjzV8QuTbhBMk73CYFpoEyFd1vZMJtpiLgdo7uU7GZ3CTzvbApYdgspWaQ9Nle+zXEB9Gd0TTrkfri1HDJ71QxK9nVOe7BEAMN2nyK81CJBMlYyforSwzRE4PMVifIJLj71Q9EGGlQIDAQAB";
    crypto.setRemotePublicKey(publicKey, 1024);

    while (!std::cin.eof()) {
        encryptRsa(&crypto);
        encryptAes(&crypto);
    }

    return 0;
}

void encryptRsa(Crypto *crypto) {
    // Get the message to encrypt
    string message = getMessage("Message to RSA encrypt: ");

    // Encrypt the message with RSA
    // +1 on the string length argument because we want to encrypt the NUL terminator too
    unsigned char *encryptedMessage = NULL;
    unsigned char *encryptedKey;
    unsigned char *iv;
    size_t encryptedKeyLength;
    size_t ivLength;

    int encryptedMessageLength = crypto->rsaEncrypt((const unsigned char *) message.c_str(), message.size() + 1,
                                                    &encryptedMessage, &encryptedKey, &encryptedKeyLength, &iv,
                                                    &ivLength);

    if (encryptedMessageLength == -1) {
        fprintf(stderr, "Encryption failed\n");
        return;
    }

    // Print the encrypted message as a base64 string
    char *b64Message = base64Encode(encryptedMessage, encryptedMessageLength);
    printf("Encrypted message: %s\n", b64Message);

    // Decrypt the message
    char *decryptedMessage = NULL;

    int decryptedMessageLength = crypto->rsaDecrypt(encryptedMessage, (size_t) encryptedMessageLength,
                                                    encryptedKey, encryptedKeyLength, iv, ivLength,
                                                    (unsigned char **) &decryptedMessage);

    if (decryptedMessageLength == -1) {
        fprintf(stderr, "Decryption failed\n");
        return;
    }

    printf("Decrypted message: %s\n", decryptedMessage);

    // Clean up
    free(encryptedMessage);
    free(decryptedMessage);
    free(encryptedKey);
    free(iv);
    free(b64Message);

    encryptedMessage = NULL;
    decryptedMessage = NULL;
    encryptedKey = NULL;
    iv = NULL;
    b64Message = NULL;
}

void encryptAes(Crypto *crypto) {
    // Get the message to encrypt
    string message = getMessage("Message to AES encrypt: ");

    // Encrypt the message with AES
    unsigned char *encryptedMessage = NULL;
    int encryptedMessageLength = crypto->aesEncrypt((const unsigned char *) message.c_str(), message.size() + 1,
                                                    &encryptedMessage);

    if (encryptedMessageLength == -1) {
        fprintf(stderr, "Encryption failed\n");
        return;
    }

    // Print the encrypted message as a base64 string
    char *b64Message = base64Encode(encryptedMessage, encryptedMessageLength);
    printf("Encrypted message: %s\n", b64Message);

    // Decrypt the message
    char *decryptedMessage = NULL;
    int decryptedMessageLength = crypto->aesDecrypt(encryptedMessage, (size_t) encryptedMessageLength,
                                                    (unsigned char **) &decryptedMessage);

    if (decryptedMessageLength == -1) {
        fprintf(stderr, "Decryption failed\n");
        return;
    }

    printf("Decrypted message: %s\n", decryptedMessage);

    // Clean up
    free(encryptedMessage);
    free(decryptedMessage);
    free(b64Message);

    encryptedMessage = NULL;
    decryptedMessage = NULL;
    b64Message = NULL;
}

string getMessage(const char *prompt) {
    string message;

    printf(prompt);
    fflush(stdout);

    getline(std::cin, message);
    return message;
}

void printKeys(Crypto *crypto) {
    // Write the RSA keys to stdout
    crypto->writeKeyToFile(stdout, KEY_SERVER_PRI);
    crypto->writeKeyToFile(stdout, KEY_SERVER_PUB);
    crypto->writeKeyToFile(stdout, KEY_CLIENT_PUB);

    // Write the AES key to stdout in hex
    unsigned char *aesKey;
    size_t aesKeyLength = crypto->getAesKey(&aesKey);
    printBytesAsHex(aesKey, aesKeyLength, "AES Key");

    // Write the AES IV to stdout in hex
    unsigned char *aesIv;
    size_t aesIvLength = crypto->getAesIv(&aesIv);
    printBytesAsHex(aesIv, aesIvLength, "AES IV");
}

void printBytesAsHex(unsigned char *bytes, size_t length, const char *message) {
    printf("%s: ", message);

    for (unsigned int i = 0; i < length; i++) {
        printf("%02hhx", bytes[i]);
    }

    puts("");
}