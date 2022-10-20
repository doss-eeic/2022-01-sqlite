#include <iostream>
#include <cstdio>
#include <string>
#include <memory>
#include "cipher.hpp"

int main(){
    unsigned char _key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    unsigned char _iv[] = {1,2,3,4,5,6,7,8};
    cipher key{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    cipher iv{1,2,3,4,5,6,7,8};
    FILE *fp_in, *fp_out;
    fp_in = fopen("plain.txt", "r");
    fp_out = fopen("cipher.dat", "w");
    if(!fp_in || !fp_out) return 1;
    int outlen = aes_encrypt(fp_in, fp_out, key, iv);
    printf("outlen = %d\n", outlen);
    fclose(fp_in);
    fclose(fp_out);
    fp_in = fopen("cipher.dat", "r");
    fp_out = fopen("decrypted.txt", "w");
    if(!fp_in || !fp_out) return 1;
    outlen = aes_decrypt(fp_in, fp_out, key, iv);
    printf("outlen = %d\n", outlen);
    fclose(fp_in);
    fclose(fp_out);
    return 0;
}
