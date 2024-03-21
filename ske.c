#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE | MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+-------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
 * +------------+--------------------+-------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY *K, unsigned char *entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	if (entropy == NULL)
	{
		randBytes(K->hmacKey, 32);
		randBytes(K->aesKey, 32);
	}
	else
	{
		unsigned char *temp;
		temp = malloc(64);
		HMAC(EVP_sha512(), KDF_KEY, 32, entropy, entLen, temp, NULL);

		for (int i = 0; i < 32; i++)
		{
			K->hmacKey[i] = temp[i];
			K->aesKey[i] = temp[i + 32];
		}

		free(temp);
	}

	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   SKE_KEY *K, unsigned char *IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	if (IV == NULL)
	{
		IV = malloc(16);
		randBytes(IV, 16);
	}
	memcpy(outBuf, IV, 16);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV) != 1)
	{
		ERR_print_errors_fp(stderr);
	}
	int nw;
	if (EVP_EncryptUpdate(ctx, outBuf + 16, &nw, inBuf, len) != 1)
	{
		ERR_print_errors_fp(stderr);
	}

	unsigned char *HMAC_Buf = malloc(HM_LEN);
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, outBuf, nw + 16, HMAC_Buf, NULL);
	memcpy(&outBuf[nw + 16], HMAC_Buf, HM_LEN);

	EVP_CIPHER_CTX_free(ctx);
	free(HMAC_Buf);

	return nw + 16 + HM_LEN; /* TODO: should return number of bytes written, which
								 hopefully matches ske_getOutputLen(...). */
}
size_t ske_encrypt_file(const char *fnout, const char *fnin,
						SKE_KEY *K, unsigned char *IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */

	int fin = open(fnin, O_RDONLY);
	if (fin == -1)
	{
		printf("Failed to open %s\n", fnin);
		return -1;
	}
	int fout = open(fnout, O_CREAT | O_RDWR, S_IRWXU);
	if (fout == -1)
	{
		printf("Failed to open %s\n", fnout);
		return -1;
	}

	struct stat buf;
	if (fstat(fin, &buf) == -1 || !buf.st_size)
	{
		return -1;
	}

	char *pa;
	pa = mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fin, 0);
	if (pa == MAP_FAILED)
	{
		return -1;
	}
	int pl = strlen(pa);

	int cipherLen = ske_getOutputLen(pl + 1);

	unsigned char *ciphertext = malloc(cipherLen + 1);

	if (IV == NULL)
	{
		IV = malloc(16);
		randBytes(IV, 16);
	}

	int encryptLen = ske_encrypt(ciphertext, (unsigned char *)pa, pl + 1, K, IV);

	if (encryptLen == -1)
	{
		printf("Failed to encrypt\n");
	}

	lseek(fout, offset_out, SEEK_SET);
	int wrs = write(fout, ciphertext, encryptLen);
	if (wrs == -1)
	{
		printf("Failed to write to file\n");
	}

	munmap(pa, buf.st_size);
	free(ciphertext);
	close(fin);
	close(fout);
	return 0;
}
size_t ske_decrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   SKE_KEY *K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	unsigned char *hmac;
	hmac = malloc(HM_LEN);
	unsigned char *IV;
	IV = malloc(16);

	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, inBuf, len - HM_LEN, hmac, NULL);

	for (int i = 0; i < HM_LEN; i++)
	{
		if (hmac[i] != inBuf[i + len - HM_LEN])
		{
			return -1;
		}
	}

	memcpy(IV, inBuf, 16);

	int cplen = len - HM_LEN - 16;
	unsigned char ciphertext[cplen];
	for (int i = 0; i < cplen; i++)
	{
		ciphertext[i] = inBuf[i + 16];
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV))
	{
		ERR_print_errors_fp(stderr);
	}

	int nw;
	if (1 != EVP_DecryptUpdate(ctx, outBuf, &nw, ciphertext, cplen))
	{
		ERR_print_errors_fp(stderr);
	}

	return nw;
}
size_t ske_decrypt_file(const char *fnout, const char *fnin,
						SKE_KEY *K, size_t offset_in)
{
	/* TODO: write this. */
	struct stat buf;

	int fin = open(fnin, O_RDONLY);
	if (fin == -1)
	{
		printf("Failed to open %s\n", fnin);
		return -1;
	}
	int fout = open(fnout, O_CREAT | O_RDWR, S_IRWXU);
	if (fout == -1)
	{
		printf("Failed to open %s\n", fnout);
		return -1;
	}

	if (fstat(fin, &buf) == -1 || !buf.st_size)
	{
		return -1;
	}

	unsigned char *pa;
	pa = mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fin, offset_in);
	if (pa == MAP_FAILED)
	{
		return -1;
	}

	int plaintextlen = buf.st_size - 16 - HM_LEN - offset_in;
	char *plaintext = malloc(plaintextlen);
	ske_decrypt((unsigned char *)plaintext, pa, buf.st_size - offset_in, K);

	close(fin);
	close(fout);

	FILE *pFile = fopen(fnout, "w");
	if (pFile != NULL)
	{
		fputs(plaintext, pFile);
		fclose(pFile);
		return 0;
	}

	printf("Error opening %s\n", fnout);
	return -1;
}