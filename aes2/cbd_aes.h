//
// Created by gj on 8/25/20.
//

#ifndef CPPRSAWITHOPENSSL_CBD_AES_H
#define CPPRSAWITHOPENSSL_CBD_AES_H

#include <string>

using namespace std;

string encrypt(string& content, int type);

string decrypt(string& content, int type);

#endif //CPPRSAWITHOPENSSL_CBD_AES_H
