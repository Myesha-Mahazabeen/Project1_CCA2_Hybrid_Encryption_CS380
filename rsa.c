#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x, 10)
#define NEWZ(x) \
	mpz_t x;    \
	mpz_init(x)
#define BYTES2Z(x, buf, len) mpz_import(x, len, -1, 1, 0, 0, buf)
#define Z2BYTES(buf, len, x) mpz_export(buf, &len, -1, 1, 0, 0, x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE *f, mpz_t x)
{
	size_t i, len = mpz_size(x) * sizeof(mp_limb_t);
	/* NOTE: len may overestimate the number of bytes actually required. */
	unsigned char *buf = malloc(len);
	Z2BYTES(buf, len, x);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++)
	{
		unsigned char b = (len >> 8 * i) % 256;
		fwrite(&b, 1, 1, f);
	}
	fwrite(buf, 1, len, f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf, 0, len);
	free(buf);
	return 0;
}
int zFromFile(FILE *f, mpz_t x)
{
	size_t i, len = 0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++)
	{
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b, 1, 1, f);
		len += (b << 8 * i);
	}
	unsigned char *buf = malloc(len);
	fread(buf, 1, len, f);
	BYTES2Z(x, buf, len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf, 0, len);
	free(buf);
	return 0;
}

void setPrime(mpz_t prime, size_t bytes){
    unsigned char* buf = malloc(bytes);
    do{
        randBytes(buf, bytes);
        BYTES2Z(prime, buf, bytes);
    }while (!ISPRIME(prime));
    free(buf);
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	rsa_initKey(K);

	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */

	// the number of bytes required for the key
    size_t keyBytes = keyBits / CHAR_BIT;

	// generate two probable prime numbers, p and q
    setPrime(K->p, keyBytes);
    setPrime(K->q, keyBytes);

	// calculate n=p*q
    mpz_mul(K->n, K->p, K->q);

	// calculate Euler's totient function φ(n)
    mpz_t phi;
    mpz_t qSubOne;
    mpz_t pSubOne;

    mpz_init(phi);
    mpz_init(qSubOne);
    mpz_init(pSubOne);

    mpz_sub_ui(pSubOne, K->p, 1);
    mpz_sub_ui(qSubOne, K->q, 1);
    mpz_mul(phi, pSubOne, qSubOne);

	// Generate a random integer prime to φ(n)
    mpz_t temp;
    mpz_init(temp);
    unsigned char* tempBuf = malloc(keyBytes);

    mpz_t one;
    
	mpz_init(one); mpz_set_ui(one, 1);

do {
    do {
        randBytes(tempBuf, keyBytes);
        BYTES2Z(K->e, tempBuf, keyBytes);
    } while (mpz_cmp_ui(K->e, 1) <= 0 || mpz_cmp(K->e, phi) >= 0); // ensure 1 < e < phi

    mpz_gcd(temp, K->e, phi);
} while (mpz_cmp_ui(temp, 1) != 0); // ensure gcd(e, phi) = 1


    mpz_invert(K->d, K->e , phi);

    free(tempBuf);
	return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
                   RSA_KEY* K) {
    // initialize to hold the input data
    mpz_t inInt;
    mpz_init(inInt);

    // convert the input byte buffer to a multi-precision integer
    BYTES2Z(inInt, inBuf, len);

    // to hold the encrypted result
    mpz_t outInt;
    mpz_init(outInt);

    // modular exponentiation to encrypt the input integer
    mpz_powm(outInt, inInt, K->e, K->n);

    // convert the encrypted multi-precision integer back to a byte buffer
    Z2BYTES(outBuf, len, outInt);

    // clean up memory
    mpz_clear(inInt);
    mpz_clear(outInt);

    // the length of the output buffer
    return len;
}


size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
                   RSA_KEY* K) {
    // initialize a multi-precision integer to hold the encrypted data
    mpz_t inInt;
    mpz_init(inInt);

    // convert the input byte buffer to a multi-precision integer
    BYTES2Z(inInt, inBuf, len);

    // initialize a multi-precision integer to hold the decrypted result
    mpz_t outInt;
    mpz_init(outInt);

    // modular exponentiation to decrypt the input integer
    mpz_powm(outInt, inInt, K->d, K->n);

    // convert the decrypted multi-precision integer back to a byte buffer
    Z2BYTES(outBuf, len, outInt);

    // clean up memory 
    mpz_clear(inInt);
    mpz_clear(outInt);

    // return the length of the output buffer
    return len;
}


size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY *K)
{
	mpz_init(K->d);
	mpz_set_ui(K->d, 0);
	mpz_init(K->e);
	mpz_set_ui(K->e, 0);
	mpz_init(K->p);
	mpz_set_ui(K->p, 0);
	mpz_init(K->q);
	mpz_set_ui(K->q, 0);
	mpz_init(K->n);
	mpz_set_ui(K->n, 0);
	return 0;
}

int rsa_writePublic(FILE *f, RSA_KEY *K)
{
	/* only write n,e */
	zToFile(f, K->n);
	zToFile(f, K->e);
	return 0;
}
int rsa_writePrivate(FILE *f, RSA_KEY *K)
{
	zToFile(f, K->n);
	zToFile(f, K->e);
	zToFile(f, K->p);
	zToFile(f, K->q);
	zToFile(f, K->d);
	return 0;
}
int rsa_readPublic(FILE *f, RSA_KEY *K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f, K->n);
	zFromFile(f, K->e);
	return 0;
}
int rsa_readPrivate(FILE *f, RSA_KEY *K)
{
	rsa_initKey(K);
	zFromFile(f, K->n);
	zFromFile(f, K->e);
	zFromFile(f, K->p);
	zFromFile(f, K->q);
	zFromFile(f, K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY *K)
{
	/* clear memory for key. */
	mpz_t *L[5] = {&K->d, &K->e, &K->n, &K->p, &K->q};
	size_t i;
	for (i = 0; i < 5; i++)
	{
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs)
		{
			memset(mpz_limbs_write(*L[i], nLimbs), 0, nLimbs * sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}