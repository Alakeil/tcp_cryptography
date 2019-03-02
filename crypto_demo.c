#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "crypto.h"


/*
 * small demo to check function correctness
 */
int
main(int argc, char **argv)
{
	char *key=aes_read_key();
	unsigned char *plaintext=(unsigned char*)"This is a test";
	unsigned char ciphertext[200],deciphertext[200];
	int cipher_len,decipher_len;
	printf("Cipher key is:\n%s\n",key);
	printf("Text to be encrypted is:\n%s\n\n",plaintext);
	cipher_len=aes_encrypt(plaintext,strlen((char*)plaintext),key,NULL,ciphertext);
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);
	decipher_len=aes_decrypt(ciphertext,cipher_len,key,NULL,deciphertext);
	deciphertext[decipher_len]='\0';
	printf("The decrypted text is:\n%s\n",deciphertext);
	
	return 0;
}

/* EOF */
