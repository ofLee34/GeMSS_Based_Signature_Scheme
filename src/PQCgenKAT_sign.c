
/*
//  PQCgenKAT_sign.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"
/* XXX I add this file for randombytes XXX */
#include "randombytes.h"


#ifdef GeMSS
    char    AlgName[] = "GeMSS";
#elif defined(BlueGeMSS)
    char    AlgName[] = "BlueGeMSS";
#elif defined(RedGeMSS)
    char    AlgName[] = "RedGeMSS";
#elif defined(FGeMSS)
    char    AlgName[] = "FGeMSS";
#elif defined(DualModeMS)
    char    AlgName[] = "DualModeMS";
#else
    char    AlgName[] = "MQsoft";
#endif

void CreateKeys( unsigned char *publickeyarray, unsigned char *secretkeyarray, unsigned long long  users );
void SignIt( unsigned char *m, unsigned long long mlen, unsigned long long smlen, unsigned long long users, unsigned char *publickeyarray, unsigned char *secretkeyarray, unsigned char *signaturearray );
void VerifyIt( unsigned char *m, unsigned long long mlen, unsigned long long smlen, unsigned long long users, unsigned char *publickeyarray, unsigned char *signaturearray);

int
main()
{
    unsigned char       m[] = "ThisIsTheMessageToBeSignedViaGeMSSBasedRingSignatureAlgorithm";   // The message to be signed
    unsigned long long  mlen = 62;      // The length of the message
    unsigned char       *sm, *m1;       // Signed and Verified messages
    unsigned long long  smlen;          // Length of signature+message
    unsigned long long  users = 50;     // Number of users in the Group R
    smlen = mlen + CRYPTO_BYTES;
    
    unsigned char *publickeyarray = (unsigned char*)malloc( users * CRYPTO_PUBLICKEYBYTES );    // Create an 2D array where each row is a public key
    unsigned char *secretkeyarray = (unsigned char*)malloc( users * CRYPTO_SECRETKEYBYTES );    // Create an 2D array where each row is a secret key
    unsigned char *signaturearray = (unsigned char*)malloc( users * CRYPTO_BYTES + mlen);       // Create an array of all signatures including fake ones
    
     
    
    /* MD: Allocate memory of signed and verified messages */
    m1 = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    sm = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    
    /* MD: Generate Public/Secret Key Pairs for all users in the group R */
    CreateKeys(publickeyarray, secretkeyarray, users);
    
    /* MD: Create a ring signature for the group G*/
    //SignIt( m, mlen, smlen, users, publickeyarray, secretkeyarray, signaturearray);
    
    /* MD: Verify the signature */
    //VerifyIt( m, mlen, smlen, users, publickeyarray, signaturearray);
    
    /**/
    for(int i = 0; i < 1000; i++)
        SignIt( m, mlen, smlen, users, publickeyarray, secretkeyarray, signaturearray);
    
    for(int i = 0; i < 1000; i++)
        VerifyIt( m, mlen, smlen, users, publickeyarray, signaturearray);
    

    free(m1);
    free(sm);
    free(publickeyarray);
    free(secretkeyarray);
    free(signaturearray);
    
    return 0;
}

void CreateKeys( unsigned char *publickeyarray, unsigned char *secretkeyarray, unsigned long long  users ){
    int i, j;
    for(i = 0; i < users; i++){
        unsigned char * sk_tmp = (unsigned char*)malloc( CRYPTO_SECRETKEYBYTES );   // Temporary secret key
        unsigned char * pk_tmp = (unsigned char*)malloc( CRYPTO_PUBLICKEYBYTES );   // Temporary public key
        
        // Create key pair
        crypto_sign_keypair(pk_tmp, sk_tmp);
        
        // Copy secretkey into 2D array
        for(j = 0; j < CRYPTO_SECRETKEYBYTES; j++){
            *(secretkeyarray + i * CRYPTO_SECRETKEYBYTES + j) = * (sk_tmp + j);
        }
        
        // Copy publickey into 2D array
        for(j = 0; j < CRYPTO_PUBLICKEYBYTES; j++){
            *(publickeyarray + i * CRYPTO_PUBLICKEYBYTES + j) = * (pk_tmp + j);
        }
        
        free(sk_tmp);
        free(pk_tmp);
    }
}

void SignIt( unsigned char *m, unsigned long long mlen, unsigned long long smlen, unsigned long long users, unsigned char *publickeyarray, unsigned char *secretkeyarray, unsigned char *signaturearray){
    int i;
    unsigned char *m1, *sm, *sm_tmp;
    unsigned long long  mlen1;
    UINT H1[SIZE_DIGEST_UINT];                                  // Hash of the message m
    UINT Hm[SIZE_SIGN_UNCOMPRESSED-SIZE_SALT_WORD];             // It will be used to XOR the S0 values for all signature verification functions
    UINT S0_Test[SIZE_SIGN_UNCOMPRESSED-SIZE_SALT_WORD]={0};    // To store S0 value for each users verification function result
    
    // Allocate memory for arrays
    m1 = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    sm = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    sm_tmp = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    
    // Initialize H1 and Hm to 0
    for(i=0; i<SIZE_DIGEST_UINT; ++i)
    {
        H1[i]=0;
    }
    for(i=0; i<SIZE_SIGN_UNCOMPRESSED-SIZE_SALT_WORD; ++i)
    {
        Hm[i]=0;
    }
    
    // Compute Hash SHA3-256 --  H1 = H(m)
    HASH((unsigned char*)H1, m, mlen);
    
    // Create fake signatures for users i=0,..,n-2 -- Last user will be the valid one.
    for(i = 0; i < (users - 1); i++){
        randombytes_NIST(signaturearray + (i * CRYPTO_BYTES), CRYPTO_BYTES);
    }
    
    // MD: Use verification function on fake signatures and XOR the results
    add_gf2m(Hm, Hm, H1);

    for(i = 0; i < (users - 1); i++){
        memcpy(sm_tmp, signaturearray + i * CRYPTO_BYTES, CRYPTO_BYTES);
        memcpy(sm_tmp+CRYPTO_BYTES,m,(size_t)mlen);
        
        // Find all S0 values for fake signatures and XOR cumulatively
        crypto_sign_open(m1, &mlen1, sm_tmp, smlen, publickeyarray + i * CRYPTO_PUBLICKEYBYTES, S0_Test);
        
        // XOR the results
        add_gf2m(Hm, Hm, S0_Test);
    }
    
    // Use XOR result as input in signature function
    crypto_sign(sm, &smlen, m, mlen, secretkeyarray + (users - 1) * CRYPTO_SECRETKEYBYTES, Hm);
    
    // Generate the signature for the group
    memcpy(signaturearray + (users - 1) * CRYPTO_BYTES, sm, smlen);
    
    free(m1);
    free(sm);
    free(sm_tmp);
}

void VerifyIt( unsigned char *m, unsigned long long mlen, unsigned long long smlen, unsigned long long users, unsigned char *publickeyarray, unsigned char *signaturearray){
    unsigned char       *m1, *sm, *sm_tmp;
    int     i;
    unsigned long long  mlen1;
    UINT H1[SIZE_DIGEST_UINT];                                  // Hash of the message m
    UINT Hm[SIZE_SIGN_UNCOMPRESSED-SIZE_SALT_WORD];             // It will be used to XOR the S0 values for all signature verification functions
    UINT S0_Test[SIZE_SIGN_UNCOMPRESSED-SIZE_SALT_WORD]={0};    // To store S0 value for each users verification function result
    
    m1 = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    sm = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    sm_tmp = (unsigned char *)calloc(mlen+CRYPTO_BYTES, sizeof(unsigned char));
    
    // MD: Initialize H1 and Hm to 0
    for(i=0; i<SIZE_DIGEST_UINT; ++i)
    {
        H1[i]=0;
    }
    for(i=0; i<SIZE_SIGN_UNCOMPRESSED-SIZE_SALT_WORD; ++i)
    {
        Hm[i]=0;
    }

    // Compute H1 = H(m)
    HASH((unsigned char*)H1, m, mlen);  // Murat was here - SHA3-256

    
    // Use verification function on fake signatures and XOR the results
    add_gf2m(Hm, Hm, H1);
    for(i = 0; i < users; i++){
        memcpy(sm_tmp, signaturearray + i * CRYPTO_BYTES, CRYPTO_BYTES);
        memcpy(sm_tmp+CRYPTO_BYTES,m,(size_t)mlen);
        
        // Find all S0 values for fake signatures and XOR cumulatively
        crypto_sign_open(m1, &mlen1, sm_tmp, smlen, publickeyarray + i * CRYPTO_PUBLICKEYBYTES, S0_Test);
        
        // XOR the results
        add_gf2m(Hm, Hm, S0_Test);
    }
    
    if( !((Hm[0] == 0) && (Hm[1] == 0) && ((Hm[2] % 4294967296) == 0)) ){  // Last 8 hexadecimal characters of Hm[2] is 0. Therefore we are looking if last 32-bits are all 0
        printf("The signature is not valid.\n");
    }
    
    free(m1);
    free(sm);
    free(sm_tmp);
}
