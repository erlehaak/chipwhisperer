/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../hal/hal.h"
#include "simpleserial.h"
#include "kem.c"
#include <string.h>

unsigned char sk[KYBER_SECRETKEYBYTES];
unsigned char pk[KYBER_PUBLICKEYBYTES];
unsigned char ss[KYBER_SSBYTES];
unsigned char send[KYBER_CIPHERTEXTBYTES];

int i = 0;

static uint8_t key_gen(uint8_t* m, uint8_t len)
{
  crypto_kem_keypair(pk, sk);
  return 0;
}

static uint8_t get_pk(uint8_t* m, uint8_t inputLen)
{
  int len = KYBER_PUBLICKEYBYTES; 

  if (i < len) {
        uint8_t chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, pk + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('p', 32, chunk);
        i += 32;
  }
  return 0;
}
static uint8_t reset_counter(uint8_t* m, uint8_t len)
{
  i = 0;
  return 0;
}

int main(void)
{
    platform_init();
	init_uart();
	trigger_setup();

    simpleserial_init();

    //Reserved simpleserial commands: 'v', 'y', 'w'
    simpleserial_addcmd('k', 0, key_gen);
    simpleserial_addcmd('p', 0, get_pk);
    simpleserial_addcmd('r', 0, reset_counter);

    //Test if Kyber is running
    crypto_kem_keypair(pk, sk); 
    crypto_kem_enc(send, ss, pk);
    crypto_kem_dec(ss, send, sk);

	while(1)
		simpleserial_get();
}
