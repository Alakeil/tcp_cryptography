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
	RSA *prv_key,*key=rsa_read_key("keys/cli_pub.pem");
	unsigned char ciphertext[1024],plaintext[1024],deciphertext[2048];
	int cipher_len,decipher_len,i;
	BIO * keybio = BIO_new(BIO_s_mem());
	RSA_print(keybio, key, 0);
	char buffer [2048];
	char *res = "";
	while (BIO_read (keybio, buffer, 2048) > 0)
	{
    		printf("%s", buffer);
	}
	BIO_free(keybio); //appropriate free "method"
	for(i=0;i<245;i++)
		plaintext[i]='a';
	plaintext[i]='\0';




	printf("Text to be encrypted is:\n%s\n\n",plaintext);
	printf("Size of message to be encrypted is %d bytes\n\n",strlen(plaintext));
	cipher_len=rsa_pub_encrypt(plaintext,strlen((char*)plaintext),key,ciphertext);
	printf("Encrypted is %d bytes!\n\n",cipher_len);
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);


	prv_key=rsa_read_key("keys/cli_priv.pem");
	decipher_len=rsa_prv_decrypt(ciphertext,cipher_len,prv_key,deciphertext);
	deciphertext[decipher_len]='\0';
	printf("Decrypted is %d bytes\n\n",decipher_len);
	printf("The decrypted text is:\n%s\n",deciphertext);
	
	return 0;
}

/* EOF */
