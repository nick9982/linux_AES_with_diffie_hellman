#include "crypto.h"

int main(int argv, char *argc[])
{
    mpz_t P, G, a, b, x, y;
    printf("Generating P(be patient, this could take up to 5 minutes).\n");
    printf("Generating a random 2048-bit prime is a strenuous process.\n");
    printf("Creating a public prime like this for diffie hellman is not\n");
    printf("something you should do everytime you establish a new\n");
    printf("connection. The G key however should be generated everytime.\n");
    Generate_Big_P(&P);
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

    char out[32];
    char buffer[32] = "encryption is fun:(";
    printf("before: ");
    for(int i = 0; i < 32; i++)
    {
        printf("%d", (unsigned char)buffer[i]);
    }
    printf("\n");
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0x00, sizeof iv);
    encrypt(buffer, key1, out, 32);
    printf("encrypted: ");
    for(int i = 0; i < 32; i++)
    {
        printf("%d", (unsigned char)out[i]);
    }
    printf("\n");
    char deca_out[32];
    decrypt(out, key2, deca_out, 32);
    printf("decrypted: ");
    for(int i = 0; i < 32; i++)
    {
        printf("%d", (unsigned char)deca_out[i]);
    }
    printf("\n");
    
    mpz_clears(P, G, a, b, x, y, NULL);

    return 0;
}
