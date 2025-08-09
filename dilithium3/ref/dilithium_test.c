
/*
 * CC0 1.0 Universal or the following MIT License
 *
 * MIT License
 *
 * Copyright (c) 2023: Hanno Becker, Vincent Hwang, Matthias J. Kannwischer, Bo-Yin Yang, and Shang-Yi Yang
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "api.h"
#include "config.h"
#include "params.h"
#include "sign.h"
#include "randombytes.h"
#include "time.h"

#define NTESTS 30
#define MLEN 59
#define CTXLEN 14

static int test_sign(void)
{
    size_t i, j;
    int ret;
    size_t mlen = 0, smlen = 0, siglen = 0;
    uint8_t b;
    uint8_t ctx[CTXLEN] = {0};
    uint8_t m[MLEN + CRYPTO_BYTES];
    uint8_t m2[MLEN + CRYPTO_BYTES];
    uint8_t sm[MLEN + CRYPTO_BYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    clock_t start_time, end_time;
    double keygen_time = 0, sign_time = 0, verify_time = 0;
    double keygen_time_avg, sign_time_avg, verify_time_avg;



    //MESSAGE GENERATION
    randombytes(m, MLEN);

    //KEY GENERATION
    start_time=clock();
    crypto_sign_keypair(pk, sk);
    end_time=clock();
    keygen_time += ((double)(end_time-start_time))/CLOCKS_PER_SEC; // Accumulate keygen time


    //SIGNATURE GENERATION

    crypto_sign_signature(sig, &siglen, m, MLEN, ctx, CTXLEN, sk); //get signature

    start_time=clock();
    crypto_sign(sm, &smlen, m, MLEN, ctx, CTXLEN, sk);
    end_time=clock();
    sign_time += ((double)(end_time-start_time))/CLOCKS_PER_SEC; // Accumulate sign time

    //SIGNATURE VERIFICATION
    start_time=clock();
    ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk); //verify signed message

    if(ret) {
    printf("Verification failed at iteration %zu\n", i);
    printf("siglen = %zu, smlen = %zu, mlen = %zu\n", siglen, smlen, mlen);
    printf("sig = ");
    for (size_t k = 0; k < siglen; ++k) {
        printf("%02x ", sig[k]);
    }
    printf("\n");
    printf("m = ");
    for (size_t k = 0; k < MLEN; ++k) {
        printf("%02x ", m[k]);
    }
    printf("\n");
    return -1;
    }
    if(smlen != MLEN + CRYPTO_BYTES) {
    printf("Signed message lengths wrong\n");
    return -1;
    }
    if(mlen != MLEN) {
    printf("Message lengths wrong\n");
    return -1;
    }
    for(j = 0; j < MLEN; ++j) {
    if(m2[j] != m[j]) {
        printf("Messages don't match\n");
        return -1;
    }
    }

    randombytes((uint8_t *)&j, sizeof(j));
    do {
    randombytes(&b, 1);
    } while(!b);
    sm[j % (MLEN + CRYPTO_BYTES)] += b;
    ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);
    if(!ret) {
    printf("Trivial forgeries possible\n");
    return -1;
    }

    end_time=clock();
    verify_time += ((double)(end_time-start_time))/CLOCKS_PER_SEC;

    /* Print average time for each operation */
    if (NTESTS > 0) {
        keygen_time_avg = keygen_time / NTESTS; // Calculate average after the loop
        printf("\nAverage time taken to generate keypair = %f", keygen_time_avg);
        sign_time_avg = sign_time / NTESTS; // Calculate average after the loop
        printf("\nAverage time taken to sign message = %f", sign_time_avg);
        verify_time_avg = verify_time / NTESTS;
        printf("\nAverage time taken to verify message = %f", verify_time_avg);
    } 
    else {
        printf("\nError: NTESTS is zero, cannot calculate average time for keypair generation.");
    }

    return 0;
}

static int test_wrong_pk(void)
{
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t pk2[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sm[MLEN + CRYPTO_BYTES];
    uint8_t m[MLEN];
    uint8_t ctx[CTXLEN] = {0};

    size_t mlen;
    size_t smlen;

    crypto_sign_keypair(pk2, sk);

    crypto_sign_keypair(pk, sk);

    randombytes(m, MLEN);
    crypto_sign(sm, &smlen, m, MLEN, ctx, CTXLEN, sk);

    // By relying on m == sm we prevent having to allocate CRYPTO_BYTES twice
    if (crypto_sign_open(sm, &mlen, sm, smlen, ctx, CTXLEN, pk2)){
        return 0;
    }
    printf("ERROR Signature did verify correctly under wrong public key!\n");
    return -1;

}

int main(void)
{
  unsigned int i;
  int r;

  for(i=0;i<NTESTS;i++) {
    r  = test_sign();
    r |= test_wrong_pk();
    if(r)
      return 1;
  }

  printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_BYTES:  %d\n",CRYPTO_BYTES);
  printf("Test successful\n");

  return 0;
}


