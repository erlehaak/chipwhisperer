#include "randombytes.h"
#include "../hal/hal.h"
#include "kem.h"
#include "simpleserial.h"

#include <string.h>

unsigned char sk[KYBER_SECRETKEYBYTES];
unsigned char pk[KYBER_PUBLICKEYBYTES];
unsigned char ss_a[KYBER_SSBYTES], ss_b[KYBER_SSBYTES];
unsigned char send[KYBER_CIPHERTEXTBYTES];

static int test_keys(void)
{
  
  
  simpleserial_put('r', 32, pk);
  //Alice generates a public key
  PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  //PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(send, ss_b, pk);

  //Alice uses Bobs response to get her secret key
  //PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ss_a, send, sk);

  simpleserial_put('f', 16, pk);
  return 0;
}

static int get_pk(void)
{
  int i;

  for (i = 0; i < KYBER_PUBLICKEYBYTES; i += 32) {
        char chunk[33]; // 32 chars plus a null terminator
        strncpy(chunk, pk + i, 32); // copy 32 chars into the chunk array
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('r', 32, chunk);
  }
  return 0;
}


int main(void)
{
  platform_init();
	init_uart();
	trigger_setup();

  simpleserial_init();

  simpleserial_addcmd('k', 128, test_keys);
  simpleserial_addcmd('p', 128, get_pk);

  while(1)
		simpleserial_get();
 
  return 0;
}
