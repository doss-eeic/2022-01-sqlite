#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <iostream>
#include <cstdio>
#include <string>
#include <memory>
#include "cipher.hpp"

int rsa_encrypt(cipher &out, cipher in, EVP_PKEY *pubkey){
    EVP_PKEY_CTX *_ctx;

    if((_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pubkey, NULL)) == NULL){
        return -1;
    }
    EVP_PKEY_CTX_ptr ctx(_ctx, EVP_PKEY_CTX_free);
    if(EVP_PKEY_CTX_is_a(ctx.get(), "RSA") != 1){
        return -1;
    }

    if(EVP_PKEY_encrypt_init(ctx.get()) != 1){
        return -1;
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) != 1){
        return -1;
    }
    std::size_t outlen;
    if(EVP_PKEY_encrypt(ctx.get(), NULL, &outlen, in.data(), in.size()) != 1){
        return -1;
    }
    out.resize(outlen);
    if(EVP_PKEY_encrypt(ctx.get(), const_cast<unsigned char*>(out.data()), &outlen, in.data(), in.size()) != 1){
        return -1;
    }
    out.resize(outlen);
    return outlen;
}


int rsa_decrypt(cipher &out, cipher in, EVP_PKEY *seckey){
    EVP_PKEY_CTX *_ctx;

    if((_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, seckey, NULL)) == NULL){
        return -1;
    }
    EVP_PKEY_CTX_ptr ctx(_ctx, EVP_PKEY_CTX_free);
    if(EVP_PKEY_CTX_is_a(ctx.get(), "RSA") != 1){
        return -1;
    }

    if(EVP_PKEY_decrypt_init(ctx.get()) != 1){
        return -1;
    }
    if(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) != 1){
        return -1;
    }
    std::size_t outlen;
    if(EVP_PKEY_decrypt(ctx.get(), NULL, &outlen, in.data(), in.size()) != 1){
        return -1;
    }
    out.resize(outlen);
    if(EVP_PKEY_decrypt(ctx.get(), const_cast<unsigned char*>(out.data()), &outlen, in.data(), in.size()) != 1){
        return -1;
    }
    out.resize(outlen);
    return outlen;
}

