#include "crypto.h"
#include <gmp.h>

int miller_rabin(mpz_t *P)
{
    int t = 0, k = 50, i, j;//k is the number of miller rabin tests that are run
    mpz_t s, max, range, rand, v;
    mpz_inits(s, rand, v, range, NULL);
    mpz_sub_ui(s, (*P), 1);
    mpz_init_set(max, s);
    mpz_sub_ui(range, max, 2);
    while(mpz_even_p(s))
    {
        mpz_div_2exp(s, s, 1);
        t++;
    }

    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    i = 0;
    while(i < k)
    {
        mpz_urandomm(rand, state, range);
        mpz_add_ui(rand, rand, 2);

        mpz_powm(v, rand, s, (*P));
        
        if(mpz_cmp_ui(v, 1) != 0)
        {
            j=0;
            while(mpz_cmp(v, max) != 0)
            {
                if(j == t-1)
                {
                    mpz_clears(rand, v, range, max, s, NULL);
                    return 0;
                }
                else
                {
                    j++;
                    mpz_powm_ui(v, v, 2, (*P));
                }
            }
        }
        i++;
    }
    mpz_clears(rand, v, range, max, s, NULL);
    return 1;
}

int isPrime(mpz_t *P)
{
    int primes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
                113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
                181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
                251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
                317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389,
                397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
                463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
                557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
                619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691,
                701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773,
                787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
                863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
                953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021,
                1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
                1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
                1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231,
                1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301,
                1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1381, 
                1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453,
                1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523,
                1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597,
                1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663,
                1667, 1669, 1693, 1697, 1709, 1721, 1723, 1733, 1741, 1747,
                1753, 1759, 1777, 1783, 1787, 1789, 1793, 1801, 1811, 1823,
                1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901,
                1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997};
    //First 303 primes to help prune out a large subset of non-primes.

    mpz_t t, r, z;
    mpz_init_set_ui(t, primes[0]);
    mpz_init_set_ui(r, primes[1]);
    mpz_init_set_str(z, "0", 1);
    if(!mpz_cmp((*P), t) && !mpz_cmp((*P), r)) return 1;
    if(!mpz_cmp((*P), z)) return 0;
    mpz_clear(z);
    mpz_clear(t);
    mpz_clear(r);
    mpz_init_set_str(t, "1", 1);
    if(mpz_even_p((*P))) //If the number is even we will add 1 to make it odd
    {
        mpz_add_ui((*P), (*P), 1);
    }
    for(int i = 0; i < 303; i++)
    {
        mpz_clear(t);
        mpz_init_set_ui(t, primes[i]);
        if(mpz_cmp((*P), t) == 0)
        {
            mpz_clear(t);
            mpz_clear(r);
            return 1;
        }
        mpz_init(r);
        mpz_tdiv_r(r, (*P), t);
        if(mpz_cmp_ui(r, 0) == 0)
        {
            mpz_clear(t);
            mpz_clear(r);
            return 0;
        }
        mpz_clear(r);
    }
    mpz_clear(t);
    return miller_rabin(&(*P));
}

void Generate_Big_P(mpz_t *P)
{
    mpz_init((*P));
    uint64_t p[32];
    int cnt = 0;
    while(1)
    {
        ssize_t r = getrandom(p, 256, GRND_RANDOM);
        if(r != 256) continue;
        mpz_import((*P), 32, -1, 64, 0, 0, &p);
        if(isPrime(&(*P))) break; 
        /* printf("%d\n", ++cnt); */
    }
}

void Generate_G_Client(mpz_t P, mpz_t *G)
{
    // Find the largest prime factor of P-1
    mpz_t q, p_minus_1, exponent;
    mpz_inits(q, p_minus_1, exponent, (*G), NULL);
    mpz_sub_ui(p_minus_1, P, 1);
    mpz_set(q, p_minus_1);
    while (mpz_even_p(q))
        mpz_div_ui(q, q, 2);

    // Seed the random number generator
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // Choose a random number between 2 and P-2
    mpz_t g;
    mpz_init(g);
    while (1)
    {
        mpz_urandomm(g, state, P);
        if (mpz_cmp_ui(g, 1) > 0 && mpz_cmp(g, p_minus_1) < 0)
        {
            // Check if g is a primitive root modulo P
            mpz_powm(exponent, g, q, P);
            if (mpz_cmp_ui(exponent, 1) != 0)
            {
                mpz_set((*G), g);
                break;
            }
        }
    }

    // Free memory
    mpz_clears(q, p_minus_1, exponent, g, NULL);
    gmp_randclear(state);
}

void generate_private_key_DH(mpz_t *K)
{
    mpz_init((*K));
    uint64_t key[4];
    while(1)
    {
        ssize_t r = getrandom(key, 32, GRND_RANDOM);
        mpz_import((*K), 4, -1, 64, 0, 0, &key);
        if(r == 32) break;
    }
}

void generate_shared_key_DH(mpz_t P, mpz_t G, mpz_t K, mpz_t *R)
{
    mpz_init((*R));
    mpz_powm((*R), G, K, P);
}

void generate_aes_key(unsigned char key[32], mpz_t P, mpz_t SK, mpz_t PK)
{
    mpz_t T;
    mpz_init(T);
    mpz_powm(T, PK, SK, P);//public key, private key, large prime
    char *diffie = mpz_get_str(NULL, 16, T);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, diffie, strlen(diffie));
    SHA256_Final(key, &sha256);

    free(diffie);
    mpz_clear(T);
}

void encrypt(char *input, unsigned char key[32], char *out, int buffer_size)
{
    AES_KEY enc_key;
    unsigned char iv[32];
    memset(iv, 0x00, sizeof iv);
    AES_set_encrypt_key(key, 256, &enc_key);
    AES_cbc_encrypt((unsigned char*)input, (unsigned char*)out, buffer_size, &enc_key, iv, AES_ENCRYPT);
}

void decrypt(char *input, unsigned char key[32], char *out, int buffer_size)
{
    AES_KEY dec_key;
    unsigned char iv[32];
    memset(iv, 0x00, sizeof iv);
    AES_set_decrypt_key(key, 256, &dec_key);
    AES_cbc_encrypt((unsigned char*)input, (unsigned char*)out, buffer_size, &dec_key, iv, AES_DECRYPT);
}
