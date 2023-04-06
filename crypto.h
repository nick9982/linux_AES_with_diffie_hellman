#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <sys/random.h>
#include <math.h>
#include <stdint.h>
#include <gmp.h>
#include <time.h>

void generate_aes_key(unsigned char[32], mpz_t, mpz_t, mpz_t);
void encrypt(char*, unsigned char[32], char*, int);
void decrypt(char*, unsigned char[32], char*, int);
void Generate_Big_P(mpz_t*);
void Generate_G_Client(mpz_t, mpz_t*);
void generate_private_key_DH(mpz_t*);
void generate_shared_key_DH(mpz_t, mpz_t, mpz_t, mpz_t*);
