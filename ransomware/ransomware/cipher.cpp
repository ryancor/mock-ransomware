#include "cipher.h"

/*
	Functions for Vigenere cipher
	Encrypt: E[i] = (P[i] + K[i]) mod 26
	Decrypt: D[i] = (E[i] - K[i] + 26) mod 26
*/

// key is based off of the size of the text its encrypting
string generateKey(string plaintext, string key)
{
	int sizeofText = plaintext.size();

	for (int i = 0; ; i++)
	{
		if (sizeofText == i)
		{
			i = 0;
		}

		if (key.size() == plaintext.size())
		{
			break;
		}
		key.push_back(key[i]);
	}
	return key;
}

string encryptText(string plaintext, string key)
{
	string cipher_text;

	for (size_t i = 0; i < plaintext.size(); i++)
	{
		// converting in range 0-25
		int eLetter = (toupper(plaintext[i]) + key[i]) % 26;

		// Convert to ASCII
		eLetter += 'A';

		cipher_text.push_back(eLetter);
	}
	return cipher_text;
}

string decryptText(string cipher_text, string key)
{
	string orig_text;

	for (size_t i = 0; i < cipher_text.size(); i++)
	{
		// converting in range 0-25
		int dLetter = (toupper(cipher_text[i]) - key[i] + 26) % 26;

		// Convert to ASCII
		dLetter += 'A';

		orig_text.push_back(dLetter);
	}
	return orig_text;
}

// XOR encryptor, decryptor
string encryptDecryptXOR(string toEncrypt)
{
	char key[10] = { 'A', '2', 'G', '6', 'J', 'L', 'C', 'C', 'Q', 'P' };
	string output = toEncrypt;
	int k_size = (sizeof(key) / sizeof(char));

	for (int i = 0; i < toEncrypt.size(); i++)
	{
		output[i] = toEncrypt[i] ^ key[i % k_size];
	}

	return output;
}