/*
** WARNING: This file is auto generated. DO NOT MODIFY
** 2015-05-29 17:18:33 -0400 by GenVectorTests-C.rb
*/
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

    (void) fprintf(stderr,"title: %s\n",title);
    (void) fprintf(stderr,"Plaintext hex: '%x'\n",plaintext_hex);
    if (*plaintext_hex == '\0')
    {
        (void) fprintf(stderr,"plaintext is NULL\n");
    }

    (void) fprintf(stderr,"title %s\n",title);
    enc_key_bin = mutils_hex_to_bin(enc_key_hex,strlen(enc_key_hex),
            &enc_key_bin_len);
    (void) fprintf(stderr,"enc key:\n");
    mutils_hex_print(stderr,enc_key_bin,enc_key_bin_len);
    (void) fprintf(stderr,"hmac key:\n");
    hmac_key_bin = mutils_hex_to_bin(hmac_key_hex,strlen(hmac_key_hex),
            &hmac_key_bin_len);
    mutils_hex_print(stderr,hmac_key_bin,hmac_key_bin_len);

    iv_bin = mutils_hex_to_bin(iv_hex,strlen(iv_hex),
            &iv_bin_len);
    (void) fprintf(stderr,"IV:\n");
    mutils_hex_print(stderr,iv_bin,iv_bin_len);
    plaintext_bin_len=0;
    plaintext_bin = mutils_hex_to_bin(plaintext_hex,strlen(plaintext_hex),
            &plaintext_bin_len);
    (void) fprintf(stderr,"Plain text len: %d\n",plaintext_bin_len);
    mutils_hex_print(stderr,plaintext_bin,plaintext_bin_len);
    (void) fprintf(stderr,"plaintext len: %d\n",plaintext_bin_len);
    ciphertext_bin = mutils_hex_to_bin(ciphertext_hex,strlen(ciphertext_hex),
            &ciphertext_bin_len);
    (void) fprintf(stderr,"cipher text in test %d bytes\n",ciphertext_bin_len);
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
    exit(1);
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


void test_v3_kdf_One_byte(void)
{
  verify_v3_kdf(
    "One byte",
    "3",
    "a",
    "0102030405060708",
    "fc632b0c a6b23eff 9a9dc3e0 e585167f 5a328916 ed19f835 58be3ba9 828797cd");
}


void test_v3_kdf_Short_password(void)
{
  verify_v3_kdf(
    "Short password",
    "3",
    "thepassword",
    "0203040506070801",
    "0ea84f52 52310dc3 e3a7607c 33bfd1eb 580805fb 68293005 da21037c cf499626");
}


void test_v3_kdf_Passphrase(void)
{
  verify_v3_kdf(
    "Passphrase",
    "3",
    "this is a bit longer password",
    "0304050607080102",
    "71343acb 1e9675b0 16ac65dc fe5ddac2 e57ed9c3 5565fdbb 2dd6d2ce fe263d5b");
}


void test_v3_kdf_Long_passphrase(void)
{
  verify_v3_kdf(
    "Long passphrase",
    "3",
    "$$$it was the epoch of belief, it was the epoch of incredulity; it was the season of Light, it was the season of Darkness; it was the spring of hope, it was the winter of despair; we had everything before us, we had nothing before us; we were all going directly to Heaven, we were all going the other way.",
    "0405060708010203",
    "11b52c50 cbf45be6 a636a314 2b8c30b8 5a624481 4a7d43e3 7457f38d e46c6735");
}


void test_v3_kdf_Multibyte(void)
{
  verify_v3_kdf(
    "Multibyte",
    "3",
    "中文密码",
    "0506070801020304",
    "d2fc3237 d4a69668 ca83d969 c2cda1ac 6c368479 2b6644b1 a90b2052 007215dd");
}


void test_v3_kdf_Mixed_language(void)
{
  verify_v3_kdf(
    "Mixed language",
    "3",
    "中文密码 with a little English, too.",
    "0607080102030405",
    "46bda5f4 65982a47 40c728bc 14c5de5c c7fc4eea f0aa41bb 9b9e8495 452dafff");
}


void test_v3_password_All_fields_empty_or_zero_with_one_byte_password_(void)
{
  verify_v3_password(
    "All fields empty or zero (with one-byte password)",
    "3",
    "a",
    "0000000000000000",
    "0000000000000000",
    "00000000000000000000000000000000",
    "",
    "03010000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 0000b303 9be31cd7 ece5e754 f5c8da17 00366631 3ae8a89d dcf8e3cb 41fdc130 b2329dbe 07d6f4d3 2c34e050 c8bd7e93 3b12");
}


void test_v3_password_One_byte(void)
{
  verify_v3_password(
    "One byte",
    "3",
    "thepassword",
    "0001020304050607",
    "0102030405060708",
    "02030405060708090a0b0c0d0e0f0001",
    "01",
    "03010001 02030405 06070102 03040506 07080203 04050607 08090a0b 0c0d0e0f 0001a1f8 730e0bf4 80eb7b70 f690abf2 1e029514 164ad3c4 74a51b30 c7eaa1ca 545b7de3 de5b010a cbad0a9a 13857df6 96a8");
}


void test_v3_password_Exactly_one_block(void)
{
  verify_v3_password(
    "Exactly one block",
    "3",
    "thepassword",
    "0102030405060700",
    "0203040506070801",
    "030405060708090a0b0c0d0e0f000102",
    "0123456789abcdef",
    "03010102 03040506 07000203 04050607 08010304 05060708 090a0b0c 0d0e0f00 01020e43 7fe80930 9c03fd53 a475131e 9a1978b8 eaef576f 60adb8ce 2320849b a32d7429 00438ba8 97d22210 c76c35c8 49df");
}


void test_v3_password_More_than_one_block(void)
{
  verify_v3_password(
    "More than one block",
    "3",
    "thepassword",
    "0203040506070001",
    "0304050607080102",
    "0405060708090a0b0c0d0e0f00010203",
    "0123456789abcdef 01234567",
    "03010203 04050607 00010304 05060708 01020405 06070809 0a0b0c0d 0e0f0001 0203e01b bda5df2c a8adace3 8f6c588d 291e03f9 51b78d34 17bc2816 581dc6b7 67f1a2e5 7597512b 18e1638f 21235fa5 928c");
}


void test_v3_password_Multibyte_password(void)
{
  verify_v3_password(
    "Multibyte password",
    "3",
    "中文密码",
    "0304050607000102",
    "0405060708010203",
    "05060708090a0b0c0d0e0f0001020304",
    "23456789abcdef 0123456701",
    "03010304 05060700 01020405 06070801 02030506 0708090a 0b0c0d0e 0f000102 03048a9e 08bdec1c 4bfe13e8 1fb85f00 9ab3ddb9 1387e809 c4ad86d9 e8a60145 57716657 bd317d4b b6a76446 15b3de40 2341");
}


void test_v3_password_Longer_text_and_password(void)
{
  verify_v3_password(
    "Longer text and password",
    "3",
    "It was the best of times, it was the worst of times; it was the age of wisdom, it was the age of foolishness;",
    "0405060700010203",
    "0506070801020304",
    "060708090a0b0c0d0e0f000102030405",
    "69 74 20 77 61 73 20 74 68 65 20 65 70 6f 63 68 20 6f 66 20 62 65 6c 69 65 66 2c 20 69 74 20 77 61 73 20 74 68 65 20 65 70 6f 63 68 20 6f 66 20 69 6e 63 72 65 64 75 6c 69 74 79 3b 20 69 74 20 77 61 73 20 74 68 65 20 73 65 61 73 6f 6e 20 6f 66 20 4c 69 67 68 74 2c 20 69 74 20 77 61 73 20 74 68 65 20 73 65 61 73 6f 6e 20 6f 66 20 44 61 72 6b 6e 65 73 73 3b 20 69 74 20 77 61 73 20 74 68 65 20 73 70 72 69 6e 67 20 6f 66 20 68 6f 70 65 2c 20 69 74 20 77 61 73 20 74 68 65 20 77 69 6e 74 65 72 20 6f 66 20 64 65 73 70 61 69 72 3b 20 77 65 20 68 61 64 20 65 76 65 72 79 74 68 69 6e 67 20 62 65 66 6f 72 65 20 75 73 2c 20 77 65 20 68 61 64 20 6e 6f 74 68 69 6e 67 20 62 65 66 6f 72 65 20 75 73 3b 20 77 65 20 77 65 72 65 20 61 6c 6c 20 67 6f 69 6e 67 20 64 69 72 65 63 74 6c 79 20 74 6f 20 48 65 61 76 65 6e 2c 20 77 65 20 77 65 72 65 20 61 6c 6c 20 67 6f 69 6e 67 20 74 68 65 20 6f 74 68 65 72 20 77 61 79 2e 0a 0a",
    "03010405 06070001 02030506 07080102 03040607 08090a0b 0c0d0e0f 00010203 0405d564 c7a99da9 21a6e7c4 078a8264 1d954795 51283167 a2c81f31 ab80c9d7 d8beb770 111decd3 e3d29bbd f7ebbfc5 f10ac87e 7e55bfb5 a7f487bc d3983570 5e83b9c0 49c6d695 2be011f8 ddb1a14f c0c92573 8de017e6 2b1d621c cdb75f29 37d0a1a7 0e44d843 b9c61037 dee2998b 2bbd740b 910232ee a7196116 8838f699 5b996417 3b34c0bc d311a2c8 7e271630 928bae30 1a8f4703 ac2ae469 9f3c285a bf1c55ac 324b073a 958ae52e e8c3bd68 f919c09e b1cd2814 2a1996a9 e6cbff5f 4f4e1dba 07d29ff6 6860db98 95a48233 140ca249 419d6304 6448db1b 0f4252a6 e4edb947 fd0071d1 e52bc156 00622fa5 48a67739 63618150 797a8a80 e592446d f5926d0b fd32b544 b796f335 9567394f 77e7b171 b2f9bc5f 2caf7a0f ac0da7d0 4d6a8674 4d6e06d0 2fbe15d0 f580a1d5 bd16ad91 34800361 1358dcb4 ac999095 5f6cbbbf b185941d 4b4b71ce 7f9ba6ef c1270b78 08838b6c 7b7ef17e 8db919b3 4fac");
}


void test_v3_key_All_fields_empty_or_zero(void)
{
  verify_v3_key(
    "All fields empty or zeroX",
    "3",
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "",
    "03000000 00000000 00000000 00000000 00000143 db63ee66 b0cdff9f 69917680 151e0e67 e6f5aea8 30ced4af ef779fe7 e5b3767e b06ea81a 0bb8a7a0 bf62c6b0 0405");
}


void test_v3_key_One_byte(void)
{
  verify_v3_key(
    "One byte",
    "3",
    "000102030405060708090a0b0c0d0e0f",
    "0102030405060708090a0b0c0d0e0f00",
    "02030405060708090a0b0c0d0e0f0001",
    "01",
    "03000203 04050607 08090a0b 0c0d0e0f 000198dc 7e36e7cc cb0cb7e8 2b048c46 0825ecd5 4ad9b093 3b236b74 8a1ce455 ee1ec4e9 3043f60b e2ed50dc cfb3c4b2 383c");
}


void test_v3_key_Exactly_one_block(void)
{
  verify_v3_key(
    "Exactly one block",
    "3",
    "0102030405060708090a0b0c0d0e0f00",
    "02030405060708090a0b0c0d0e0f0001",
    "030405060708090a0b0c0d0e0f000102",
    "000102030405060708090a0b0c0d0e0f",
    "03000304 05060708 090a0b0c 0d0e0f00 01029228 f6538960 defc04a2 be30eee6 665ea738 f6c2f3fa 2b73c2ed bbe3a0d5 7f59d197 45313f9e a7ede5bb 6b1bd56f 2ff331dd d22f25dc 99bc11f3 d7ebbf49 14bc");
}


void test_v3_key_More_than_one_block(void)
{
  verify_v3_key(
    "More than one block",
    "3",
    "02030405060708090a0b0c0d0e0f0001",
    "030405060708090a0b0c0d0e0f000102",
    "0405060708090a0b0c0d0e0f00010203",
    "000102030405060708090a0b0c0d0e0f 000102030405060708",
    "03000405 06070809 0a0b0c0d 0e0f0001 0203a7c3 b4598b47 45fb62fb 266a54ee c7dcddc9 73d5ecb8 93586198 5407d656 2314d01f d9cddf52 859611d6 e917b6e2 40f82aa5 a508ddd8 8960df8b ceea3aeb e9de");
}

int main(int argc,char **argv)
{
    test_v3_kdf_One_byte();
    test_v3_kdf_Short_password();
    test_v3_kdf_Passphrase();
    test_v3_kdf_Long_passphrase();
    test_v3_kdf_Multibyte();
    test_v3_kdf_Mixed_language();
    test_v3_password_All_fields_empty_or_zero_with_one_byte_password_();
    test_v3_password_One_byte();
    test_v3_password_Exactly_one_block();
    test_v3_password_More_than_one_block();
    test_v3_password_Multibyte_password();
    test_v3_password_Longer_text_and_password();
    test_v3_key_All_fields_empty_or_zero();
    test_v3_key_One_byte();
    test_v3_key_Exactly_one_block();
    test_v3_key_More_than_one_block();
    return(0);
}
