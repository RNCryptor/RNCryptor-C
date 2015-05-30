#include "rncryptor_c.h"
#include "mutils.h"

/*
** Part of RNCryptor-C
*/
void verify_v3_key(const char *title,
        const char *version,
        const char *enc_key_hex,
        const char *hmac_key_hex,
        const char *iv_hex,
        const char *plaintext_hex,
        const char *ciphertext_hex)
{
    unsigned char
        *enc_key_bin,
        *hmac_key_bin,
        *iv_bin,
        *plaintext_bin,
        *ciphertext_bin;
    int
        enc_key_bin_len,
        hmac_key_bin_len,
        iv_bin_len,
        plaintext_bin_len,
        ciphertext_bin_len;

    unsigned char
        *cipher_text;
    int
        cipher_text_len;

    char
        errbuf[BUFSIZ];

    (void) fprintf(stderr,"veriry_v3_key title: %s\n",title);

    (void) fprintf(stderr,"title %s\n",title);
    enc_key_bin = mutils_hex_to_bin(enc_key_hex,strlen(enc_key_hex),
            &enc_key_bin_len);
    (void) fprintf(stderr,"enc key: %d\n",enc_key_bin_len);
    mutils_hex_print(stderr,enc_key_bin,enc_key_bin_len);
    hmac_key_bin = mutils_hex_to_bin(hmac_key_hex,strlen(hmac_key_hex),
            &hmac_key_bin_len);
    (void) fprintf(stderr,"hmac key: %d\n",hmac_key_bin_len);
    mutils_hex_print(stderr,hmac_key_bin,hmac_key_bin_len);

    iv_bin = mutils_hex_to_bin(iv_hex,strlen(iv_hex),
            &iv_bin_len);
    (void) fprintf(stderr,"IV: %d\n",iv_bin_len);
    mutils_hex_print(stderr,iv_bin,iv_bin_len);
    (void) fprintf(stderr,"plaintext hex %02x",plaintext_hex);
    plaintext_bin = mutils_hex_to_bin(plaintext_hex,strlen(plaintext_hex),
            &plaintext_bin_len);
    (void) fprintf(stderr,"Plain text len: %d\n",plaintext_bin_len);
    mutils_hex_print(stderr,plaintext_bin,plaintext_bin_len);
    (void) fprintf(stderr,"plaintext len: %d\n",plaintext_bin_len);
    ciphertext_bin = mutils_hex_to_bin(ciphertext_hex,strlen(ciphertext_hex),
            &ciphertext_bin_len);
    (void) fprintf(stderr,"cipher text in test\n");
    mutils_hex_print(stderr,ciphertext_bin,ciphertext_bin_len);
    rncryptorc_set_debug(1);
    cipher_text = rncryptorc_encrypt_data_with_key_iv(plaintext_bin,
        plaintext_bin_len,
        RNCRYPTOR3_KDF_ITER,
        enc_key_bin,
        hmac_key_bin,
        iv_bin,
        &cipher_text_len,
        errbuf,
        sizeof(errbuf)-1);
    (void) fprintf(stderr,"errbuf: %s\n",errbuf);
    (void) fprintf(stderr,"%s,len:%d\n",title,cipher_text_len);
    mutils_hex_print(stderr,cipher_text,cipher_text_len);
}

void verify_v3_password(const char *title,
        const char *version,
        const char *password,
        const char *enc_salt_hex,
        const char *hmac_salt_hex,
        const char *iv_hex,
        const char *plaintext_hex,
        const char *ciphertext_hex)
{
    unsigned char
        *enc_salt_bin,
        *hmac_salt_bin,
        *iv_bin,
        *plaintext_bin,
        *ciphertext_bin;
    int
        passowrd_len = 0,
        enc_salt_bin_len = 0,
        hmac_salt_bin_len = 0,
        plaintext_bin_len = 0,
        iv_bin_len = 0,
        ciphertext_bin_len = 0;

    unsigned char
        *cipher_text;
    int
        cipher_text_len = 0;

    char
        errbuf[BUFSIZ];

    enc_salt_bin = mutils_hex_to_bin(enc_salt_hex,strlen(enc_salt_hex),
            &enc_salt_bin_len);

//    (void) fprintf(stderr,"ENC Salt:\n");
//    mutils_hex_print(stderr,enc_salt_bin,enc_salt_bin_len);

    hmac_salt_bin = mutils_hex_to_bin(hmac_salt_hex,strlen(hmac_salt_hex),
            &hmac_salt_bin_len);
//    (void) fprintf(stderr,"HMAC Salt:\n");
//    mutils_hex_print(stderr,hmac_salt_bin,hmac_salt_bin_len);

    iv_bin = mutils_hex_to_bin(iv_hex,strlen(iv_hex),
            &iv_bin_len);
//    (void) fprintf(stderr,"iv: %d\n",iv_bin_len);
//    mutils_hex_print(stderr,iv_bin,iv_bin_len);

    plaintext_bin = mutils_hex_to_bin(plaintext_hex,strlen(plaintext_hex),
            &plaintext_bin_len);
//    (void) fprintf(stderr,"Plaintext:\n");
//    mutils_hex_print(stderr,plaintext_bin,plaintext_bin_len);

    ciphertext_bin = mutils_hex_to_bin(ciphertext_hex,strlen(ciphertext_hex),
            &ciphertext_bin_len);
//    mutils_hex_print(stderr,ciphertext_bin,ciphertext_bin_len);

//    rncryptorc_set_debug(1);
    cipher_text = rncryptorc_encrypt_data_with_password_with_salts_and_iv(plaintext_bin,
            plaintext_bin_len,
            10000,
            password,strlen(password),
            enc_salt_bin,
            hmac_salt_bin,
            iv_bin,
            &cipher_text_len,
            errbuf,
            sizeof(errbuf)-1);
//    mutils_hex_print(stderr,cipher_text,cipher_text_len);
    if (memcmp(ciphertext_bin,cipher_text,cipher_text_len) == 0)
    {
        (void) fprintf(stderr,">>>>>>>>>>>>>> %s: OK\n",title);
    }
    else
    {
        (void) fprintf(stderr,"%s: OK\n",title);
    }
}

void verify_v3_kdf(const char *title,
        const char *version,
        const char *password,
        const char *salt_hex,
        const char *key_hex)
{
}
