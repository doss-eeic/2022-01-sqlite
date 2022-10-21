#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <iostream>
#include <cstdio>
#include <string>
#include <memory>
#include "cryption.hpp"

#define DEBUG 0

int aes_encrypt(FILE *fp_in, FILE *fp_out, const cipher key, const cipher iv) noexcept{
    EVP_CIPHER_CTX *_ctx;
    if((_ctx = EVP_CIPHER_CTX_new()) == NULL){
        return -1;
    }
    EVP_CIPHER_CTX_ptr ctx(_ctx, EVP_CIPHER_CTX_free);
    if(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1){
        return -1;
    }

    u_char *indata = new u_char[1024];
    u_char *outdata = new u_char[1056];

    int inlen, outlen, totallen = 0, tmplen;
    while((inlen = fread(indata, 1, 1024, fp_in)) != 0){
        EVP_EncryptUpdate(ctx.get(), outdata, &outlen, indata, inlen);
        #if DEBUG
        printf("outlen: %d\n", outlen);
        #endif
        fwrite(outdata, 1, outlen, fp_out);
        totallen += outlen;
    }
    EVP_EncryptFinal_ex(ctx.get(), outdata, &outlen);
    #if DEBUG
    printf("finallen: %d\n", outlen);
    #endif
    fwrite(outdata, 1, outlen, fp_out);
    totallen += outlen;
    delete[] indata;
    delete[] outdata;
    return totallen;
}

int aes_decrypt(FILE *fp_in, FILE *fp_out, const cipher key, const cipher iv) noexcept{
    EVP_CIPHER_CTX *_ctx;
    if((_ctx = EVP_CIPHER_CTX_new()) == NULL){
        return -1;
    }
    EVP_CIPHER_CTX_ptr ctx(_ctx, EVP_CIPHER_CTX_free);
    if(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1){
        return -1;
    }

    u_char *indata = new u_char[1024];
    u_char *outdata = new u_char[1056];

    int inlen, outlen, totallen = 0, tmplen;
    while((inlen = fread(indata, 1, 1024, fp_in)) != 0){
        EVP_DecryptUpdate(ctx.get(), outdata, &outlen, indata, inlen);
        #if DEBUG
        printf("outlen: %d\n", outlen);
        #endif
        fwrite(outdata, 1, outlen, fp_out);
        totallen += outlen;
    }
    EVP_DecryptFinal_ex(ctx.get(), outdata, &outlen);
    #if DEBUG
    printf("finallen: %d\n", outlen);
    #endif
    fwrite(outdata, 1, outlen, fp_out);
    totallen += outlen;
    delete[] indata;
    delete[] outdata;
    return totallen;
}