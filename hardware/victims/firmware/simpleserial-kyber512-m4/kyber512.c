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
#include "params.h"
#include "indcpa.h"
#include "randombytes.h"
#include <string.h>

uint8_t sk[KYBER_SECRETKEYBYTES]; //1632 bytes != length KYBER_INDCPA_SECRETKEYBYTES)
uint8_t pk[KYBER_PUBLICKEYBYTES];          // = KYBER_INDCPA_PUBLICKEYBYTES
uint8_t ct[KYBER_CIPHERTEXTBYTES]; //768 byte = KYBER_INDCPA_BYTES 
uint8_t m_input[KYBER_INDCPA_MSGBYTES];
uint8_t m_output[KYBER_INDCPA_MSGBYTES];
//uint8_t m_output[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,255};
uint8_t coin[KYBER_SYMBYTES];


int i = 0;

static uint8_t key_gen(uint8_t* m, uint8_t len)
{
  indcpa_keypair(pk, sk);
  return 0;
}

static uint8_t encrypt(uint8_t* m, uint8_t len)
{
  randombytes(coin, KYBER_SYMBYTES); //Random coin
  indcpa_enc(ct , m_input, pk, coin);
  return 0;
}

static uint8_t decrypt(uint8_t* m, uint8_t len)
{ 
  trigger_high();
  indcpa_dec(m_output, ct, sk);
  trigger_low(); 
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

static uint8_t get_sk(uint8_t* m, uint8_t inputLen)
{
  int len = KYBER_SECRETKEYBYTES; //1632 bytes

  if (i < len) {
        uint8_t chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, pk + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('s', 32, chunk);
        i += 32;
  }
  return 0;
}

static uint8_t get_ct(uint8_t* m, uint8_t inputLen)
{
  int len = KYBER_CIPHERTEXTBYTES; //768 bytes

  if (i < len) {
        uint8_t chunk[33]; // 32 chars plus a null terminator       
        memcpy(chunk, ct + i, 32); // copy next 32 chars into the chunk array        
        chunk[32] = '\0'; // add a null terminator to the end of the chunk
        simpleserial_put('c', 32, chunk);
        i += 32;
  }
  return 0;
}

static uint8_t get_plaintext_input(uint8_t* m, uint8_t len){
  randombytes(m_input, KYBER_INDCPA_MSGBYTES); // Generate new random input message
  simpleserial_put('i', KYBER_INDCPA_MSGBYTES, m_input);
  return 0;
}

static uint8_t get_plaintext_output(uint8_t* m, uint8_t len){
  simpleserial_put('o', KYBER_INDCPA_MSGBYTES, m_output);
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
  /*
  //Reserved simpleserial commands: 'v', 'y', 'w'
  simpleserial_addcmd('k', 0, key_gen);
  simpleserial_addcmd('e', 0, encrypt);
  simpleserial_addcmd('d', 0, decrypt);
  
  simpleserial_addcmd('r', 0, reset_counter);
  
  simpleserial_addcmd('p', 0, get_pk);
  simpleserial_addcmd('s', 0, get_sk);
  simpleserial_addcmd('c', 0, get_ct);
  simpleserial_addcmd('i', 0, get_plaintext_input);
  simpleserial_addcmd('o', 0, get_plaintext_output);
  
  while(1)
		simpleserial_get();
  
  */
  //Test just cpa functions
  
  //randombytes(m_input, KYBER_INDCPA_MSGBYTES); //random input plaintext
  randombytes(coin, KYBER_SYMBYTES);  //random coins
  
  indcpa_keypair(pk, sk);
  indcpa_enc(ct , m_input, pk, coin);
  indcpa_dec(m_output, ct, sk);
  
  //simpleserial_put('i', KYBER_INDCPA_MSGBYTES, m_input);
  //simpleserial_put('o', KYBER_INDCPA_MSGBYTES, m_output);

	
}
