#include "kem.h"
#include <stdio.h>

uint8_t sk[KYBER_SECRETKEYBYTES];
uint8_t pk[KYBER_PUBLICKEYBYTES];
uint8_t ss_a[KYBER_SSBYTES], ss_b[KYBER_SSBYTES];
uint8_t ct[KYBER_CIPHERTEXTBYTES];

void printarray(uint8_t *array, size_t size){
    
    for(int i=0; i<size; i++) {
        printf("%d ", array[i]);
    }
    printf("\n\n");
}

int main(void)
{   

    PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk);
    PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(ct, ss_a, pk);
    PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss_b, ct, sk);

    printf("Public key:\n");
    printarray(pk, sizeof(pk));
    printf("Secret key:\n");
    printarray(sk, sizeof(sk));
    printf("Shared secrets:\n");
    printarray(ss_a, sizeof(ss_a));
    printarray(ss_b, sizeof(ss_b));

    return 0;
}