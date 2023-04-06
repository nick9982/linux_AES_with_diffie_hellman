#include "crypto.h"
#include <time.h>

int main(int argv, char *argc[])
{
    mpz_t P, G, a, b, x, y;
    printf("Generating P(be patient, this could take up to 5 minutes).\n");
    printf("Generating a random 2048-bit prime is a strenuous process.\n");
    printf("Creating a public prime like this for diffie hellman is not\n");
    printf("something you should do everytime you establish a new\n");
    printf("connection. The G key however should be generated everytime.\n");
    time_t start = clock();
    Generate_Big_P(&P);
    time_t end = clock() - start;
    printf("Generating G\n");
    Generate_G_Client(P, &G);
    printf("Generating priv keys\n");
    generate_private_key_DH(&a);
    generate_private_key_DH(&b);
    printf("Generating shared keys\n");
    generate_shared_key_DH(P, G, a, &x); //alice shares key x
    generate_shared_key_DH(P, G, b, &y); //bob shares key y

    unsigned char key1[32];
    unsigned char key2[32];
    printf("Generating aes keys\n");
    generate_aes_key(key1, P, a, y);
    generate_aes_key(key2, P, b, x);
    printf("key 1: ");
    for(int i = 0; i < 32; i++)
    {
        printf("%d", key1[i]);
    }
    printf("\n");
    printf("key 2: ");
    for(int i = 0; i < 32; i++)
    {
        printf("%d", key2[i]);
    }
    printf("\n");
    printf("As you can see, the keys resulting from the key exchange are the\n");
    printf("same. As the result of diffie-hellman will provide a shared key between\n");
    printf("without sharing a secret key. In this case, the secret key was variable 'a'\n");
    printf("for one user and variable 'b' for the other user. 'x' and 'y' were the\n");
    printf("respective public key that was shared with the other user.\n");
    printf("\nNow the encrytion begins\n");

    char out[32];
    char buffer[32] = "encryption is fun:(";
    printf("before: %s\n", buffer);
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, sizeof iv);
    printf("User 1 is encrypting with key 1...\n");
    encrypt(buffer, key1, out, 32);
    printf("encrypted: ");
    for(int i = 0; i < 32; i++)
    {
        printf("%d", (unsigned char)out[i]);
    }
    printf("\n");
    char deca_out[32];
    printf("User 2 is decrypting with key 2...\n");
    decrypt(out, key2, deca_out, 32);
    printf("decrypted: %s\n", deca_out);
    
    mpz_clears(P, G, a, b, x, y, NULL);

    return 0;
}
