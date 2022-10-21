#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string>
#include <cassert>
#include "cryption.hpp"

int hybrid_new_encrypt(FILE *fp_in, FILE *fp_out, u_char *slot, size_t *slotsize, EVP_PKEY *pubkey){
    u_char keybuf[KEYSIZE];
    u_char ivbuf[IVSIZE];
    RAND_bytes(keybuf, sizeof(keybuf));
    RAND_bytes(ivbuf, sizeof(ivbuf));
    cipher key(keybuf, KEYSIZE);
    cipher iv(ivbuf, IVSIZE);
    assert(key.size() == KEYSIZE);
    assert(iv.size() == IVSIZE);
    cipher _slot;
    if(rsa_encrypt(_slot, key + iv, pubkey) < 0){
        return -1;
    }
    if(slot == NULL){
        *slotsize = _slot.size();
        return 0;
    }
    if(_slot.size() > *slotsize){
        return -1;
    }
    *slotsize = _slot.size();
    _slot.copy(slot, *slotsize);
    int outlen;
    if((outlen = aes_encrypt(fp_in, fp_out, key, iv)) < 0){
        return -1;
    }
    return outlen;
}

int hybrid_decrypt(FILE *fp_in, FILE *fp_out, const u_char *slot, size_t slotsize, EVP_PKEY *seckey){
    cipher key_iv;
    cipher _slot(slot, slotsize);
    if(rsa_decrypt(key_iv, _slot, seckey) != KEYSIZE + IVSIZE){
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