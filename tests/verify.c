#include "rncryptor_c.h"
#include "mutils.h"

/*
** Part of RNCryptor-C. Code for testing RNCryptor's test vectors
** This block of code comes from verify.c
*/
/************** block starts ******************/
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

    enc_key_bin = mutils_hex_to_bin(enc_key_hex,strlen(enc_key_hex),
            &enc_key_bin_len);
    hmac_key_bin = mutils_hex_to_bin(hmac_key_hex,strlen(hmac_key_hex),
            &hmac_key_bin_len);

    iv_bin = mutils_hex_to_bin(iv_hex,strlen(iv_hex),
            &iv_bin_len);

    plaintext_bin = mutils_hex_to_bin(plaintext_hex,strlen(plaintext_hex),
            &plaintext_bin_len);
    ciphertext_bin = mutils_hex_to_bin(ciphertext_hex,strlen(ciphertext_hex),
            &ciphertext_bin_len);
    rncryptorc_set_debug(0);
    cipher_text = rncryptorc_encrypt_data_with_key_iv(plaintext_bin,
        plaintext_bin_len,
        RNCRYPTOR3_KDF_ITER,
        enc_key_bin,
        hmac_key_bin,
        iv_bin,
        &cipher_text_len,
        errbuf,
        sizeof(errbuf)-1);
    if (memcmp(ciphertext_bin,cipher_text,cipher_text_len) == 0)
    {
        (void) fprintf(stderr," %s: PASSED\n",title);
    }
    else
    {
        (void) fprintf(stderr," %s: FAILED\n",title);
    }
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

    hmac_salt_bin = mutils_hex_to_bin(hmac_salt_hex,strlen(hmac_salt_hex),
            &hmac_salt_bin_len);

    iv_bin = mutils_hex_to_bin(iv_hex,strlen(iv_hex),
            &iv_bin_len);

    plaintext_bin = mutils_hex_to_bin(plaintext_hex,strlen(plaintext_hex),
            &plaintext_bin_len);

    ciphertext_bin = mutils_hex_to_bin(ciphertext_hex,strlen(ciphertext_hex),
            &ciphertext_bin_len);

    rncryptorc_set_debug(0);
    cipher_text = rncryptorc_encrypt_data_with_password_with_salts_and_iv(plaintext_bin,
            plaintext_bin_len,
            RNCRYPTOR3_KDF_ITER,
            password,strlen(password),
            enc_salt_bin,
            hmac_salt_bin,
            iv_bin,
            &cipher_text_len,
            errbuf,
            sizeof(errbuf)-1);
    if (memcmp(ciphertext_bin,cipher_text,cipher_text_len) == 0)
    {
        (void) fprintf(stderr," %s: PASSED\n",title);
    }
    else
    {
        (void) fprintf(stderr,"  %s: FAILED\n",title);
    }
}

/*
** this is actually a test for OpenSSL's
** PKCS5_PBKDF2_HMAC_SHA1() function
*/
void verify_v3_kdf(const char *title,
        const char *version,
        const char *password,
        const char *salt_hex,
        const char *key_hex)
{
    unsigned char
        key[32],
        *salt_bin,
        *key_bin;
    int
        rc,
        salt_bin_len = 0,
        key_bin_len = 0;

    salt_bin = mutils_hex_to_bin(salt_hex,strlen(salt_hex),
            &salt_bin_len);
    key_bin = mutils_hex_to_bin(key_hex,strlen(key_hex),
            &key_bin_len);
    rc = PKCS5_PBKDF2_HMAC_SHA1(password,strlen(password),
            salt_bin,
            8,
            RNCRYPTOR3_KDF_ITER,
            32,
            key); /* key is returend */
    if (rc == 1)
    {
        if (memcmp(key_bin,key,32) == 0)
        {
        (void) fprintf(stderr," %s: PASSED\n",title);
        }
        else
        {
            (void) fprintf(stderr,"  %s: FAILED\n",title);
        }
    }
}
/************** block ends ******************/
