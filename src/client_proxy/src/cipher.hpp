#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <memory>

#define KEYSIZE 32
#define IVSIZE 16
#define BLOCKSIZE IVSIZE

using cipher = std::basic_string<unsigned char>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

int rsa_encrypt(cipher &out, cipher in, EVP_PKEY *pubkey);
int rsa_decrypt(cipher &out, cipher in, EVP_PKEY *seckey);
int aes_encrypt(FILE *fp_in, FILE *fp_out, cipher key, cipher iv);
int aes_decrypt(FILE *fp_in, FILE *fp_out, cipher key, cipher iv);
int hybrid_new_encrypt(FILE *fp_in, FILE *fp_out, EVP_PKEY *pubkey, cipher &slot);
int hybrid_decrypt(FILE *fp_in, FILE *fp_out, EVP_PKEY *seckey, cipher slot);
