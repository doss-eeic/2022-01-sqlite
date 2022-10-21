#include <iostream>
#include <cstdio>
#include <string>
#include <memory>
#include "cryption.hpp"

int main(int argc, char **argv){
    if(argc < 2) return 1;
    FILE *fp_key, *fp;
    if((fp_key = fopen(argv[1], "r")) == NULL) return 1;

    unsigned char mes[] = {'h', 'e', 'l', 'l', 'o'};
    cipher message(mes);
    cipher out;
    cipher dec;
    EVP_PKEY *_pubkey = NULL;
    if(PEM_read_PUBKEY(fp_key, &_pubkey, NULL, NULL) == NULL){
        std::cout << "failed to read public key" << std::endl;
        return 1;
    }
    EVP_PKEY_ptr pubkey(_pubkey, EVP_PKEY_free);

    if(rsa_encrypt(out, message, pubkey.get()) > 0){
        std::cout << "encrypted size: " << out.size() << std::endl;
        fclose(fp_key);
    }else{
        std::cout << "failed to encrypt" << std::endl;
        return 1;
    }

    if(argc > 2){
        fp_key = fopen(argv[2], "r");
        EVP_PKEY *_seckey = NULL;
        if(PEM_read_PrivateKey(fp_key, &_seckey, NULL, NULL) == NULL){
            std::cout << "failed to read private key" << std::endl;
            return 1;
        }
        EVP_PKEY_ptr seckey(_seckey, EVP_PKEY_free);
        int outlen;
        if((outlen = rsa_decrypt(dec, out, seckey.get())) > 0){
            if(message == dec){
                std::cout << "successfully decrypted" << std::endl;
            }else{
                std::cout << "decrypted data is not match initial data" << std::endl;
                fwrite(dec.data(), 1, dec.size(), stdout);
                return 1;
            }           
            fclose(fp_key);
        }
        else{
            std::cout << "failed to decrypt" << std::endl;
        }
    }
    return 0;
}