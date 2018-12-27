#include <iostream>
#include <string>

using namespace std;

// keyword can't not be longer than the word its being generated against : (TODO) BUG FIX
static string keyword = "BULLOCKS";

string generateKey(string plaintext, string key);
string encryptText(string plaintext, string key);
string decryptText(string cipher_text, string key);

string encryptDecryptXOR(string toEncrypt);