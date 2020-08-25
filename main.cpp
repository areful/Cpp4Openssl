//
// Created by areful on 2020/07/09/.
//

#include "b64/test_b64.h"
#include "rsa/test_rsa.h"
#include "aes/test_aes.h"

int main(int argc, char *argv[]) {
    test_base64();
    test_rsa();
    test_aes();

    return 0;
}
