#include "../kyber512clean/randombytes.h"
#include "../hal/hal.h"
#include "../kyber512clean/api.h"
#include "simpleserial.h"

#include <string.h>

#define NTESTS 10

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
//#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_BYTES           //NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_PUBLICKEYBYTES  //NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES  //NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_CIPHERTEXTBYTES //NAMESPACE(CRYPTO_CIPHERTEXTBYTES)
#define MUPQ_CRYPTO_ALGNAME //NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_kem_keypair //NAMESPACE(crypto_kem_keypair)
#define MUPQ_crypto_kem_enc //NAMESPACE(crypto_kem_enc)
#define MUPQ_crypto_kem_dec //NAMESPACE(crypto_kem_dec)

const uint8_t canary[8] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
};

/* allocate a bit more for all keys and messages and
 * make sure it is not touched by the implementations.
 */
static void write_canary(uint8_t *d) {
  for (size_t i = 0; i < 8; i++) {
    d[i] = canary[i];
  }
}

struct test
{
  unsigned char key_a[MUPQ_CRYPTO_BYTES+16], key_b[MUPQ_CRYPTO_BYTES+16];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES+16];
  unsigned char sendb[MUPQ_CRYPTO_CIPHERTEXTBYTES+16];
  unsigned char sk_a[MUPQ_CRYPTO_SECRETKEYBYTES+16];
};


static int test_keys(void)
{
  
  unsigned char key_a[MUPQ_CRYPTO_BYTES+16], key_b[MUPQ_CRYPTO_BYTES+16];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES+16];
  unsigned char sendb[MUPQ_CRYPTO_CIPHERTEXTBYTES+16];
  unsigned char sk_a[MUPQ_CRYPTO_SECRETKEYBYTES+16];

 // write_canary(key_a); write_canary(key_a+sizeof(key_a)-8);
 // write_canary(key_b); write_canary(key_b+sizeof(key_b)-8);
 // write_canary(pk); write_canary(pk+sizeof(pk)-8);
 // write_canary(sendb); write_canary(sendb+sizeof(sendb)-8);
 // write_canary(sk_a); write_canary(sk_a+sizeof(sk_a)-8);

  simpleserial_put('r', 16, pk);

  //Alice generates a public key
  MUPQ_crypto_kem_keypair(pk+8, sk_a+8);


  //Bob derives a secret key and creates a response
  MUPQ_crypto_kem_enc(sendb+8, key_b+8, pk+8);

  //Alice uses Bobs response to get her secret key
  MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

  simpleserial_put('1', 16, pk);
  return 0;
}



int main(void)
{
  platform_init();
	init_uart();
	trigger_setup();

  simpleserial_init();

  test_keys();

  while(1)
		simpleserial_get();
 
  return 0;
}
