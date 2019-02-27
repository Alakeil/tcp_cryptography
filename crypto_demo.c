#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "cs457_crypto.h"


/*
 * small demo to check function correctness
 */
int
main(int argc, char **argv)
{
	char *key=aes_read_key();
	unsigned char *iv=(unsigned char*)"0123456789012345";
	unsigned char *plaintext=(unsigned char*)"This is a test";
	unsigned char ciphertext[200];
	int cipher_len;
	printf("Cipher key is:\n%s\n",key);
	printf("Text to be encrypted is:\n%s\n\n",plaintext);
	cipher_len=aes_encrypt(plaintext,strlen((char*)plaintext),key,iv,ciphertext);
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);
	return 0;
}

/* EOF */
