#include "cbd_aes.h"
#include <string>
#include <iostream>

using namespace std;

int main() {
    string content = "Hello, AES cipher!";
    string encrypted = encrypt(content, 1);
    cout << encrypted << endl;

    string decrypted = decrypt(encrypted, 1);
    cout << decrypted << endl;

    return 0;
}
