#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>


/* error reporting helpers */
#define ERRX(ret, str) \
    do { fprintf(stderr, str "\n"); exit(ret); } while (0)
#define ERR(ret, str) \
    do { fprintf(stderr, str ": %s\n", strerror(errno)); exit(ret); } while (0)

/* buffer size */
#define BUFLEN	2048

/* key files*/
#define AES_KF		"keys/aes_key.txt"
#define S_PUB_KF	"keys/srv_pub.pem"
#define S_PRV_KF	"keys/srv_priv.pem"
#define C_PUB_KF	"keys/cli_pub.pem"
#define C_PRV_KF	"keys/cli_priv.pem"

/* AES block size */
#define AES_BS 16


/* --------------------------- conversion helpers --------------------------- */


/*
 * converts half printable hex value to integer
 */
int
half_hex_to_int(unsigned char c)
{
	if (isdigit(c))
		return c - '0';

	if ((tolower(c) >= 'a') && (tolower(c) <= 'f'))
		return tolower(c) + 10 - 'a';

	return 0;
}


/*
 * converts a printable hex array to bytes
 */
char *
hex_to_bytes(char *input)
{
	int i;
	char *output;

	output = NULL;
	if (strlen(input) % 2 != 0)
		ERRX(0, "reading hex string");

	output = calloc(strlen(input) / 2, sizeof(unsigned char));
	if (!output)
		ERRX(1, "h2b calloc");

	for (i = 0; i < strlen(input); i+= 2) {
		output[i / 2] = ((unsigned char)half_hex_to_int(input[i])) *
		    16 + ((unsigned char)half_hex_to_int(input[i + 1]));
	}
	
	return output;
}


/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/* ----------------------------- key management ----------------------------- */


/*
 * retrieves an AES key from the key file
 */
unsigned char *
aes_read_key(void)
{

}


/* 
 * retrieves an RSA key from the key file
 */
RSA *
rsa_read_key(char *kfile)
{

}


/* ----------------------------- AES functions ------------------------------ */


/*
 * encrypts the data with 128-bit AES ECB
 */
int
aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext)
{

}


/*
 * decrypts the data and returns the plaintext size
 */
int
aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext)
{

}


/* ----------------------------- RSA functions ------------------------------ */


/*
 * RSA public key encryption
 */
int
rsa_pub_encrypt(unsigned char *plaintext, int plaintext_len,
    RSA *key, unsigned char *ciphertext)
{

}


/*
 * RSA private key decryption
 */
int
rsa_prv_decrypt(unsigned char *ciphertext, int ciphertext_len,
    RSA *key, unsigned char *plaintext)
{

}


/*
 * RSA private key encryption
 */
int
rsa_prv_encrypt(unsigned char *plaintext, int plaintext_len,
    RSA *key, unsigned char *ciphertext)
{

}


/*
 * RSA public key decryption
 */
int
rsa_pub_decrypt(unsigned char *ciphertext, int ciphertext_len,
    RSA *key, unsigned char *plaintext)
{

}


/*
 * RSA Public(Private) encryption
 */
int
rsa_pub_priv_encrypt(unsigned char *plaintext, int plaintext_len,
    RSA *pub_k, RSA *priv_k, unsigned char *ciphertext)
{

}


/*
 * RSA Public(Private) decryption
 */
int
rsa_pub_priv_decrypt(unsigned char *ciphertext, int ciphertext_len,
    RSA *pub_k, RSA *priv_k, unsigned char *plaintext)
{

}

/* EOF */
