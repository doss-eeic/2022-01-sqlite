#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iostream>
#include <cstdio>
#include <cassert>
#include <string>
#include <memory>
#include "cipher.hpp"

int hybrid_new_encrypt(FILE *fp_in, FILE *fp_out, EVP_PKEY *pubkey, cipher &slot){
    unsigned char keybuf[KEYSIZE];
    unsigned char ivbuf[IVSIZE];
    RAND_bytes(keybuf, sizeof(keybuf));
    RAND_bytes(ivbuf, sizeof(ivbuf));
    cipher key(keybuf, KEYSIZE);
    cipher iv(ivbuf, IVSIZE);
    assert(key.size() == KEYSIZE);
    assert(iv.size() == IVSIZE);
    int outlen;
    if((outlen = aes_encrypt(fp_in, fp_out, key, iv)) < 0){
        return -1;
    }
    if(rsa_encrypt(slot, key + iv, pubkey) < 0){
        return -1;
    }
    return outlen;
}

int hybrid_decrypt(FILE *fp_in, FILE *fp_out, EVP_PKEY *seckey, cipher slot){
    cipher key_iv;
    if(rsa_decrypt(key_iv, slot, seckey) != KEYSIZE + IVSIZE){
        return -1;
    }
    cipher key(key_iv.substr(0, KEYSIZE));
    cipher iv(key_iv.substr(KEYSIZE, IVSIZE));
    int outlen;
    if((outlen = aes_decrypt(fp_in, fp_out, key, iv)) < 0){
        return -1;
    }
    return outlen;
}