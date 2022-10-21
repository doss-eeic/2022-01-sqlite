#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include "cryption.hpp"

// ./api_test pubkey plaintext encrypted_data [seckey decrypted_data]

int main(int argc, char **argv){
    if(argc < 4) return 1;
    FILE *fp_key, *fp_in, *fp_out, *fp_dec;
    if(!(fp_key = fopen(argv[1], "r")) ) return 1;
    if(!(fp_in = fopen(argv[2], "r")) ) return 1;
    if(!(fp_out = fopen(argv[3], "w")) ) return 1;

    int outlen;
    EVP_PKEY *pubkey = NULL;
    if(PEM_read_PUBKEY(fp_key, &pubkey, NULL, NULL) == NULL){
        puts("failed to read public key");
        return 1;
    }
    size_t slotlen;
    if(hybrid_new_encrypt(fp_in, fp_out, NULL, &slotlen, pubkey) < -1){
        printf("failed to get slot size");
        return 1;
    }
    u_char *slot = malloc(slotlen);
    if((outlen = hybrid_new_encrypt(fp_in, fp_out, slot, &slotlen, pubkey)) >= 0){
        printf("encrypted size: %d\n", outlen);
        printf("slot size: %d\n", slotlen);
    }else{
        puts("failed to encrypt");
        return 1;
    }
    EVP_PKEY_free(pubkey);
    fclose(fp_key);
    fclose(fp_in);
    fclose(fp_out);

    if(argc > 5){
        if(!(fp_key = fopen(argv[4], "r"))) return 1;
        if(!(fp_in = fopen(argv[3], "r"))) return 1;
        if(!(fp_out = fopen(argv[5], "w"))) return 1;
        EVP_PKEY *seckey = NULL;
        if(PEM_read_PrivateKey(fp_key, &seckey, NULL, NULL) == NULL){
            puts("failed to read private key");
            return 1;
        }
        if((outlen = hybrid_decrypt(fp_in, fp_out, slot, slotlen, seckey)) >= 0){
            printf("decrypted size: %d\n", outlen);
        }
        else{
            puts("failed to decrypt");
        }
        EVP_PKEY_free(seckey);
    }
    free(slot);
    return 0;
}