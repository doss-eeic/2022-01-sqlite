#include <iostream>
#include <cstdio>
#include <string>
#include <memory>
#include "cryption.hpp"


int main(int argc, char **argv){
    if(argc < 4) return 1;
    FILE *fp_key, *fp_in, *fp_out, *fp_dec;
    if(!(fp_key = fopen(argv[1], "r")) ) return 1;
    if(!(fp_in = fopen(argv[2], "r")) ) return 1;
    if(!(fp_out = fopen(argv[3], "w")) ) return 1;

    cipher slot;
    int outlen;
    EVP_PKEY *_pubkey = NULL;
    if(PEM_read_PUBKEY(fp_key, &_pubkey, NULL, NULL) == NULL){
        std::cout << "failed to read public key" << std::endl;
        return 1;
    }
    EVP_PKEY_ptr pubkey(_pubkey, EVP_PKEY_free);
    if((outlen = hybrid_new_encrypt(fp_in, fp_out, slot, pubkey.get())) >= 0){
        std::cout << "encrypted size: " << outlen << std::endl;
        std::cout << "slot size: " << slot.size() << std::endl;
    }else{
        std::cout << "failed to encrypt" << std::endl;
        return 1;
    }
    fclose(fp_key);
    fclose(fp_in);
    fclose(fp_out);

    if(argc > 5){
        if(!(fp_key = fopen(argv[4], "r"))) return 1;
        if(!(fp_in = fopen(argv[3], "r"))) return 1;
        if(!(fp_out = fopen(argv[5], "w"))) return 1;
        EVP_PKEY *_seckey = NULL;
        if(PEM_read_PrivateKey(fp_key, &_seckey, NULL, NULL) == NULL){
            std::cout << "failed to read private key" << std::endl;
            return 1;
        }
        EVP_PKEY_ptr seckey(_seckey, EVP_PKEY_free);
        if((outlen = hybrid_decrypt(fp_in, fp_out, slot, seckey.get())) >= 0){
            std::cout << "decrypted size: " << outlen << std::endl;
        }
        else{
            std::cout << "failed to decrypt" << std::endl;
        }
    }
    return 0;
}