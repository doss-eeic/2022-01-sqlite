#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <sys/types.h>

#define KEYSIZE 32
#define IVSIZE 16
#define BLOCKSIZE IVSIZE

#ifdef __cplusplus

#include <memory>


using cipher = std::basic_string<u_char>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

int rsa_encrypt(cipher &out, const cipher in, EVP_PKEY *pubkey) noexcept;
int rsa_decrypt(cipher &out, const cipher in, EVP_PKEY *seckey) noexcept;
int aes_encrypt(FILE *fp_in, FILE *fp_out, const cipher key, const cipher iv) noexcept;
int aes_decrypt(FILE *fp_in, FILE *fp_out, const cipher key, const cipher iv) noexcept;
int hybrid_new_encrypt(FILE *fp_in, FILE *fp_out, cipher &slot, EVP_PKEY *pubkey) noexcept;
int hybrid_decrypt(FILE *fp_in, FILE *fp_out, const cipher slot, EVP_PKEY *seckey) noexcept;

extern "C" {
#endif
    /* maybe in no use
    int rsa_encrypt(u_char out, size_t &outlen, u_char *in, size_t insize, EVP_PKEY *pubkey);
    int rsa_decrypt(u_char out, size_t &outlen, u_char *in, size_t insize, EVP_PKEY *seckey);
    int aes_encrypt(FILE *fp_in, FILE *fp_out, u_char key[KEYSIZE], u_char iv[IVSIZE]);
    int aes_decrypt(FILE *fp_in, FILE *fp_out, u_char key[KEYSIZE], u_char iv[IVSIZE]);
    */
    // encrypts data read from fp_in, using rsa pubkey. slotsize should be initialized with 
    // the length of slot. encrypted data is written to fp_out and generated key and its size 
    // is written to slot and slotsize.  if slot is NULL, it returns 0 and writes excepted size to slotsize.
    // the returned values is the size of encrypted data if successfully encrypted, otherwise -1.
    int hybrid_new_encrypt(FILE *fp_in, FILE *fp_out, u_char *slot, size_t *slotsize, EVP_PKEY *pubkey);
    // decrypts data read from fp_in using rsa seckey and slot, writes the decrypted data to fp_out 
    // and returns the size if successfully decrypted, otherwise -1.
    int hybrid_decrypt(FILE *fp_in, FILE *fp_out, const u_char *slot, size_t slotsize, EVP_PKEY *seckey);
#ifdef __cplusplus
}
#endif