#include "rncryptor_c.h"
#include "mutils.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/*
** as per:
** https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md
** muquit@muquit.com 
** Documentation is in the header file rncryptor_c.h
*/
static const char *libname = "libcryptorc";
static int sdebug = 0;

typedef struct _RNCryptorInfo
{
    /* data format starts */
    unsigned char
        version,
        options;

    unsigned char
        encryption_salt[8];

    unsigned char
        hmac_salt[8];

    unsigned char
        iv[16];

    unsigned char
        *cipher_text;

    unsigned long
        cipher_text_length;

    unsigned char
        hmac[32];
    /* data format ends */

    unsigned char
        encr_key[32],
        hmac_key[32];

    const char
        *infile_path;

    MutilsBlob
        *blob;

    int
        kdf_iter;

    unsigned int
        header_size;
}RNCryptorInfo;


/* function prototypes -starts-*/
static void log_err(const char *fmt, ...);
static void log_debug(const char *fmt, ...);
static RNCryptorInfo *allocate_rncryptor_info(void);
static void free_rncryptor_info(RNCryptorInfo *ci);
static RNCryptorInfo *decode_encrypted_blob(MutilsBlob *blob);
static int verify_hmac(RNCryptorInfo *ci,const char *password,
        int password_len);
/* function prototypes -ends-*/

#define CHECK_MALLOC(p) \
do \
{ \
    if (p == NULL) \
    {\
        log_err("%s (%d) - ERROR: memory allocation problem\n",__FILE__,__LINE__); \
        goto ExitProcessing; \
    }\
}while(0)
/*
** from: https://cryptocoding.net/index.php/Coding_rules#Compare_secret_strings_in_constant_time
** compare in constant time
** Issue# 1
*/
int util_cmp_const(const void * a, const void *b, const size_t size) 
{
  const unsigned char *_a = (const unsigned char *) a;
  const unsigned char *_b = (const unsigned char *) b;
  unsigned char result = 0;
  size_t i;
 
  for (i = 0; i < size; i++) {
    result |= _a[i] ^ _b[i];
  }
 
  return result; /* returns 0 if equal, nonzero otherwise */
}

/* id is 0 or 1 */
void rncryptorc_set_debug(int d)
{
    sdebug = d;
    if (d == 1)
    {
        (void) fprintf(stderr," (Compiled with OpenSSL version: %s)\n",
                   SSLeay_version(SSLEAY_VERSION));
    }
}

/*
** Write log message to stderr
*/
static void log_err(const char *fmt, ...)
{
    va_list
        args;

    va_start(args, fmt);
    vfprintf(stderr,fmt,args);
    va_end(args);
}
static void log_debug(const char *fmt, ...)
{
    va_list
        args;

    char
        buf2[1024],
        buf[1024];
    if (!sdebug)
    {
        return;
    }

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    snprintf(buf2, sizeof(buf2), "%s: %s", libname, buf);
    (void) fprintf(stderr,"%s\n",buf2);
    (void)fflush(stderr);
    va_end(args);
}

unsigned char *rncryptorc_decrypt_file_with_password(const char *infile_path,
        int kdf_iter,
        const char *password,
        int password_length,
        int *outdata_len,
        char *errbuf,
        int errbuf_len)
{
    MutilsBlob
        *blob = NULL;

    unsigned char
        *outdata = NULL;

    *outdata_len = 0;
    blob = mutils_file_to_blob(infile_path);
    if (blob == NULL)
    {
        (void)snprintf(errbuf,errbuf_len-1,
                "Error: could not open file %s for reading",infile_path);
        return(NULL);
    }
    log_debug("%s:%d - input data size %d bytes",
            MCFL,
            blob->length);
    outdata = rncryptorc_decrypt_data_with_password(blob->data,
            blob->length,
            kdf_iter,
            password,password_length,
            outdata_len,
            errbuf,errbuf_len);
    mutils_destroy_blob(blob);
    return (outdata);
}

unsigned char *rncryptorc_decrypt_file_with_key(const char *infile_path,
        int kdf_iter,
        const unsigned char *encr_key,
        const unsigned char *hmac_key,
        int *outdata_len,
        char *errbuf,
        int errbuf_len)
{
    MutilsBlob
        *blob = NULL;
    unsigned char
        *outdata = NULL;

    blob = mutils_file_to_blob(infile_path);
    if (blob == NULL)
    {
        (void)snprintf(errbuf,errbuf_len-1,
                "Error: could not open file %s for reading",
                infile_path);
        return(NULL);
    }
    outdata = rncryptorc_decrypt_data_with_key(blob->data,blob->length,
            kdf_iter,
            encr_key,
            hmac_key,
            outdata_len,
            errbuf,
            errbuf_len);
    mutils_destroy_blob(blob);
    return(outdata);
}

unsigned char *rncryptorc_encrypt_file_with_password(const char *infile_path,
        int kdf_iter,
        const char *password,
        int password_length,
        int *outdata_len,
        char *errbuf,
        int errbuf_len)
{
    MutilsBlob
        *blob = NULL;

    unsigned char
        *outdata = NULL;

    blob = mutils_file_to_blob(infile_path);
    if (blob == NULL)
    {
        (void)snprintf(errbuf,errbuf_len-1,
                "Error: could not open file %s for reading",infile_path);
        return(NULL);
    }

    log_debug("%s:%d - input data size %d bytes",
            MCFL,
            blob->length);
    outdata = rncryptorc_encrypt_data_with_password(blob->data,
            blob->length,
            kdf_iter,
            password,password_length,
            outdata_len,
            errbuf,errbuf_len);
    mutils_destroy_blob(blob);
    return(outdata);
}

unsigned char *rncryptorc_encrypt_file_with_key(const char *infile_path,
        int kdf_iter,
        const unsigned char *encr_key,
        const unsigned char *hmac_key,
        int *outdata_len,
        char *errbuf,
        int errbuf_len)
{
    MutilsBlob
        *blob = NULL;

    unsigned char
        *outdata = NULL;


    /* read the input file as a blob */
    blob = mutils_file_to_blob(infile_path);
    if (blob == NULL)
    {
        (void)snprintf(errbuf,errbuf_len-1,
                "Error: could not open file %s for reading",infile_path);
        return(NULL);
    }
    outdata = rncryptorc_encrypt_data_with_key(blob->data,
            blob->length,
            kdf_iter,
            encr_key,
            hmac_key,
            outdata_len,
            errbuf,
            errbuf_len);
    mutils_destroy_blob(blob);
    return(outdata);
}

/*
** Allocate memory and initialize values to default
*/
static RNCryptorInfo *allocate_rncryptor_info(void)
{
    RNCryptorInfo *ci = (RNCryptorInfo *)malloc(sizeof(RNCryptorInfo));
    CHECK_MALLOC(ci);
    memset(ci,0,sizeof(RNCryptorInfo));
    ci->version = RNCRYPTOR_DATA_FORMAT_VERSION;
    /* initialize to password based encr/decr */
    ci->options = 0x1;
    ci->header_size =
          1   /* version */
        + 1   /* options */
        + 8   /* encryption salt */
        + 8   /* HMAC salt */
        + 16; /* IV */
    ci->kdf_iter = RNCRYPTOR3_KDF_ITER;

    return ci;
ExitProcessing:
    return(NULL);
}

static void free_rncryptor_info(RNCryptorInfo *ci)
{
    if (ci)
    {
        if (ci->cipher_text)
        {
            (void)free((char *)ci->cipher_text);
        }
        (void) free((char *)ci);
    }
}

static RNCryptorInfo *decode_encrypted_blob(MutilsBlob *blob)
{
    RNCryptorInfo
        *ci = NULL;

    ci = allocate_rncryptor_info();
    if (!ci)
    {
        goto ExitProcessing;
    }
    ci->blob = blob;

    /* version */
    ci->version = mutils_read_blob_byte(blob);
    /* update code when version changes */
    if (ci->version != RNCRYPTOR_DATA_FORMAT_VERSION)
    {
        log_err("Error: Unsupported RNCryptor data format version %02x",ci->version);
        goto ExitProcessing;
    }

    /* options */
    ci->options = mutils_read_blob_byte(blob);

    if (ci->options == 0x01) /* password based */
    {
        /* encryption salt */
        mutils_read_blob(blob,sizeof(ci->encryption_salt),ci->encryption_salt);

        /* hmac salt */
        mutils_read_blob(blob,sizeof(ci->hmac_salt),ci->hmac_salt);
    }
    else
    {
        /* update header size. default is password based */
        ci->header_size =
            1   /* version */
          + 1   /* option */
          + 16; /* IV */
    }

    /* iv */
    mutils_read_blob(blob,sizeof(ci->iv),ci->iv);

    /* done reading header. now find out the length of cypther text */
    ci->cipher_text_length = blob ->length - sizeof(ci->hmac) - ci->header_size;
    log_debug("%s:%d  - Cipher text length %lu",
            MCFL,
            ci->cipher_text_length);

    ci->cipher_text =
        (unsigned char *)malloc(ci->cipher_text_length * sizeof(unsigned char *));;
    CHECK_MALLOC(ci->cipher_text);
    mutils_read_blob(blob,ci->cipher_text_length,ci->cipher_text);
    mutils_read_blob(blob,sizeof(ci->hmac),ci->hmac);

    if (blob->length != blob->offset)
    {
        log_err("ERROR: Corrupt encrypted file: %s",ci->infile_path);
        goto ExitProcessing;
    }

    return(ci);

ExitProcessing:
    if (ci)
    {
        free_rncryptor_info(ci);
    }
    return(NULL);
}

/*
** returns SUCCESS or FAILRUE
** if key based encryption/decryption is used, pass ci->hmac_key, also pass
** password as NULL and length of pasword as 0
*/
static int verify_hmac(RNCryptorInfo *ci,const char *password, int password_len)
{
    unsigned char
        hmac_sha256[32];

    const EVP_MD
        *sha256=NULL;

    HMAC_CTX
        hmac_ctx;

    unsigned int
        hmac_len;

    int
        rc;

    if (ci == NULL)
    {
        return(FAILURE);
    }

    if (password != NULL) 
    {
        /* Derive hmac key from password using hmac salt and iteration as per RFC2898 */
        rc = PKCS5_PBKDF2_HMAC_SHA1(password, password_len,
                ci->hmac_salt,
                sizeof(ci->hmac_salt),
                ci->kdf_iter,
                sizeof(ci->hmac_key),
                ci->hmac_key); /* ci->hmac_key is returend */

        if (rc != 1)
        {
            log_err("ERROR: Could not derive key from password with hmac salt and iter");
            goto ExitProcessing;
        }
    }
    else
    {
        /* caller must pass ci->hmac_key */
    }


    /*
    ** calculate HMAC-SHA256 of (data-32) and compare that with the HMAC-SHA256 
    ** which is the last 32 bytes of the data
    */
    sha256 = EVP_sha256();
    HMAC_CTX_init(&hmac_ctx);
    HMAC_Init(&hmac_ctx,ci->hmac_key,32,sha256);
    HMAC_Update(&hmac_ctx,ci->blob->data,ci->blob->length - 32);
    HMAC_Final(&hmac_ctx,hmac_sha256,&hmac_len);
    HMAC_CTX_cleanup(&hmac_ctx);
/*    rc = memcmp(ci->hmac,hmac_sha256,32); */
    rc = util_cmp_const(ci->hmac,hmac_sha256,32);
    if (rc != 0)
    {
        log_err("ERROR: Could not verify HMAC");
        goto ExitProcessing;
    }

    return SUCCESS;

ExitProcessing:
    return(FAILURE);
}

unsigned char *rncryptorc_encrypt_data_with_password(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const char *password,
        int password_length,
        int *outdata_len,
        char *errbuf,
        int errbuf_len)
{
    int
        rc=FAILURE;

    unsigned char
        encr_salt_8[8],
        hmac_salt_8[8],
        iv_16[16];

    unsigned char
        *output = NULL;

    *outdata_len = 0;
    log_debug("%s:%d - verifying input",MCFL);
    if (errbuf_len <= 0)
    {
        log_err("ERROR:Invalid errbuf len %d",errbuf_len);
        goto ExitProcessing;
    }

    memset(errbuf,0,errbuf_len);
    memset(encr_salt_8,0,8);
    memset(hmac_salt_8,0,8);
    memset(iv_16,0,16);
    /* input can be empty */
    if (password == NULL || *password == '\0')
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Password can not be NULL");
        goto ExitProcessing;
    }
    if (password_length <= 0)
    {
        (void)snprintf(errbuf,errbuf_len-1,"Invalid password length %d",password_length);
        goto ExitProcessing;
    }

    /* 8 byte hmac salt */
    rc = RAND_bytes(hmac_salt_8,8);
    if (rc != 1)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Could not generate random HMAC salt");
        goto ExitProcessing;
    }

    /* 8 byte encryption salt, we're using password */
    rc = RAND_bytes(encr_salt_8,8);
    if (rc != 1)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Could not generate random encryption salt");
        goto ExitProcessing;
    }

    /* 16 byte iv */
    rc = RAND_bytes(iv_16,16);
    if (rc != 1)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Could not generate random IV");
        goto ExitProcessing;
    }

    output = rncryptorc_encrypt_data_with_password_with_salts_and_iv(indata,
        indata_len,
        kdf_iter,
        password,
        password_length,
        encr_salt_8,
        hmac_salt_8,
        iv_16,
        outdata_len,
        errbuf,
        errbuf_len);

ExitProcessing:
    return(output);
}

unsigned char *rncryptorc_encrypt_data_with_password_with_salts_and_iv(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const char *password,
        int password_length,
        unsigned char *encr_salt_8,
        unsigned char *hmac_salt_8,
        unsigned char *iv_16,
        int *outdata_len,
        char *errbuf,
        int errbuf_len)
{
    RNCryptorInfo
        *ci = NULL;

    MutilsBlob
        *blob = NULL;

    EVP_CIPHER_CTX
        cipher_ctx;

    HMAC_CTX
        hmac_ctx;

    int
        rc=FAILURE;

    const EVP_MD
        *sha256 = NULL;

    int
        outlen1 = 0,
        outlen2 = 0;

    unsigned int
        hmac_len;

    unsigned char
        hmac_sha256[32];

    unsigned char
        *output = NULL;

    unsigned int
        blocksize = 16;

    unsigned char
        *ciphertext = NULL;

    unsigned char
        encr_key[32],
        hmac_key[32];

    int
        ciphertext_len;


    log_debug("%s:%d - verifying input",MCFL);
    if (errbuf_len <= 0)
    {
        log_err("ERROR:Invalid errbuf len %d",errbuf_len);
        goto ExitProcessing;
    }

    memset(errbuf,0,errbuf_len);
    memset(encr_key,0,sizeof(encr_key));
    memset(hmac_key,0,sizeof(hmac_key));
    if (password == NULL || *password == '\0')
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Password can not be NULL");
        goto ExitProcessing;
    }
    if (password_length <= 0)
    {
        (void)snprintf(errbuf,errbuf_len-1,"Invalid password length %d",password_length);
        goto ExitProcessing;
    }

    ci = allocate_rncryptor_info();
    if (!ci)
    {
        goto ExitProcessing;
    }
    ci->options = 0x01;

    /* Derive cipher key from password using encr salt and iteration as per RFC2898 */
    log_debug("%s:%d - Deriving Cipher key with salt, iterations %d",
            MCFL,
            kdf_iter);

    rc = PKCS5_PBKDF2_HMAC_SHA1(password,password_length,
            encr_salt_8,
            8,
            kdf_iter,
            32,
            encr_key); /* encr_key is returend */
    if (rc != 1)
    {
        log_err("ERROR: Could not derive key from password with encr salt and iter");
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Could not derive key from password with encr salt and iter");
        goto ExitProcessing;
    }
    EVP_EncryptInit(&cipher_ctx,EVP_aes_256_cbc(),encr_key,iv_16);
    blocksize = EVP_CIPHER_CTX_block_size(&cipher_ctx);
    log_debug("%s:%d - Block size: %ld",MCFL,blocksize);

    if (indata == NULL && indata_len == 0)
    {
        blob = mutils_allocate_blob(blocksize);
    }
    else
    {
        blob = mutils_allocate_blob(indata_len);
    }
    CHECK_MALLOC(blob);
    log_debug("%s:%d - input data size %d bytes",
            MCFL,
            indata_len);
    log_debug("%s:%d - Encoding",MCFL);

    /*
    ** Encode. memory will be re-allocated for blob if needed.
    */

    /* version */
    mutils_write_blob_byte(blob,ci->version);

    /* options */
    mutils_write_blob_byte(blob,ci->options);

    /* 8 byte encryption salt, we're using password */
    mutils_write_blob(blob,8,encr_salt_8);

    /* 8 byte hmac salt */
    mutils_write_blob(blob,8,hmac_salt_8);

    /* 16 byte iv */
    mutils_write_blob(blob,16,iv_16);

    log_debug("%s:%d - Deriving HMAC key with salt, iterations %d",
            MCFL,
            kdf_iter);
    /* Derive HMAC key from password using hmac salt and iteration as per RFC2898 */
    rc = PKCS5_PBKDF2_HMAC_SHA1(password,password_length,
            hmac_salt_8,
            8,
            kdf_iter,
            32,
            hmac_key); /* hmac_key is returend */
    if (rc != 1)
    {
        log_err("ERROR: Could not derive key from password with hmac salt and iter");
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Could not derive key from password with hmac salt and iter");
        goto ExitProcessing;
    }

    log_debug("%s:%d - Encrypting..",MCFL);
    /* allocate space for cipher text */
    ciphertext_len = indata_len + blocksize - (indata_len % blocksize);
    ciphertext = (unsigned char *) malloc(ciphertext_len * sizeof(unsigned char));
    CHECK_MALLOC(ciphertext);

    EVP_EncryptUpdate(&cipher_ctx,ciphertext,&outlen1,indata,indata_len);
    EVP_EncryptFinal(&cipher_ctx,ciphertext + outlen1,&outlen2);
    EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    mutils_write_blob(blob,outlen1 + outlen2,ciphertext);

    log_debug("%s:%d - Plain text length: %d",MCFL,indata_len);
    log_debug("%s:%d - Cipther text length: %d",MCFL,outlen1 + outlen2);
    log_debug("%s:%d - Padding %d bytes",
            MCFL,
            (ciphertext_len - indata_len));
    log_debug("%s:%d - outdata len: %d",MCFL,outlen1 + outlen2);

    log_debug("%s:%d - calculating HMAC-SHA256",MCFL);
    /* calculate HMAC-SHA256 */
    sha256 = EVP_sha256();
    HMAC_CTX_init(&hmac_ctx);
    HMAC_Init(&hmac_ctx,hmac_key,sizeof(hmac_key),sha256);
    HMAC_Update(&hmac_ctx,blob->data,blob->length);
    HMAC_Final(&hmac_ctx,hmac_sha256,&hmac_len);
    HMAC_CTX_cleanup(&hmac_ctx);

    mutils_write_blob(blob,hmac_len,hmac_sha256);
    log_debug("%s:%d - Output lenth %lu",MCFL,blob->length);

    output = (unsigned char *)malloc(blob->length * sizeof(unsigned char));
    CHECK_MALLOC(output);

    memcpy(output,blob->data,blob->length);
    *outdata_len = blob->length;
ExitProcessing:
    if (ci)
    {
        free_rncryptor_info(ci);
    }

    if (blob)
    {
        mutils_destroy_blob(blob);
    }
    if (ciphertext)
    {
        (void)free((char *)ciphertext);
    }
    return(output);
}

unsigned char *rncryptorc_encrypt_data_with_key(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const unsigned char *encr_key,
        const unsigned char *hmac_key,
        int *outdata_len,
        char *errbuf,
        int errbuf_len)
{
    unsigned char
        iv_16[16];

    unsigned char
        *output = NULL;

    int
        rc;

    *outdata_len = 0;
    memset(iv_16,0,16);
    log_debug("%s:%d - verifying input",MCFL);
    if (errbuf_len <= 0)
    {
        log_err("ERROR:Invalid errbuf len %d",errbuf_len);
        goto ExitProcessing;
    }

    memset(errbuf,0,errbuf_len);

    /* generate 16 byte iv */
    rc = RAND_bytes(iv_16,16);
    if (rc != 1)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Could not generate secure random IV");
        goto ExitProcessing;
    }
    output = rncryptorc_encrypt_data_with_key_iv(indata,
        indata_len,
        kdf_iter,
        encr_key,
        hmac_key,
        iv_16,
        outdata_len,
        errbuf,
        errbuf_len);

ExitProcessing:
    return(output);
}

unsigned char *rncryptorc_encrypt_data_with_key_iv(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const unsigned char *encr_key_32,
        const unsigned char *hmac_key_32,
        const unsigned char *iv_16,
        int *outdata_len,
        char *errbuf,
        int errbuf_len)
{
    RNCryptorInfo
        *ci = NULL;

    MutilsBlob
        *blob = NULL;

    EVP_CIPHER_CTX
        cipher_ctx;

    HMAC_CTX
        hmac_ctx;

    const EVP_MD
        *sha256 = NULL;

    int
        outlen1 = 0,
        outlen2 = 0;

    unsigned int
        hmac_len;

    unsigned char
        hmac_sha256[32];

    unsigned char
        *output = NULL;

    unsigned int
        blocksize = 16;

    unsigned char
        *ciphertext = NULL;

    int
        ciphertext_length;



    log_debug("%s:%d - verifying input",MCFL);
    if (errbuf_len <= 0)
    {
        log_err("ERROR:Invalid errbuf len %d",errbuf_len);
        goto ExitProcessing;
    }

    memset(errbuf,0,errbuf_len);
    EVP_EncryptInit(&cipher_ctx,EVP_aes_256_cbc(),encr_key_32,iv_16);
    blocksize = EVP_CIPHER_CTX_block_size(&cipher_ctx);
    log_debug("%s:%d - Block size: %ld",MCFL,blocksize);

    if (indata == NULL && indata_len == 0)
    {
        /* memory will be re-allocated as needed */
        blob = mutils_allocate_blob(blocksize);
    }
    else
    {
        /* memory will be re-allocated as needed */
        blob = mutils_allocate_blob(indata_len);
    }
    CHECK_MALLOC(blob);
    log_debug("%s:%d - input data size %d bytes",
            MCFL,
            indata_len);

    ci = allocate_rncryptor_info();
    if (!ci)
    {
        goto ExitProcessing;
    }

    /* version */
    mutils_write_blob_byte(blob,ci->version);

    /* options */
    ci->options = 0x00;
    mutils_write_blob_byte(blob,ci->options);

    /* 16 byte iv */
    mutils_write_blob(blob,16,iv_16);

    log_debug(":%s:%d - Encrypting,",MCFL);

    /* allocate space for cipher text */
    ciphertext_length =
          indata_len + blocksize - (indata_len % blocksize);
    ciphertext =
        (unsigned char *) malloc(ciphertext_length * sizeof(unsigned char));
    CHECK_MALLOC(ciphertext);
    log_debug("%s:%d - Plain text length: %d",MCFL,indata_len);
    log_debug("%s:%d - Cipther text length: %d",MCFL,ciphertext_length);
    log_debug("%s:%d - Padding %d bytes",
            MCFL,(ciphertext_length - indata_len));

    EVP_EncryptUpdate(&cipher_ctx,ciphertext,&outlen1,indata,indata_len);
    EVP_EncryptFinal(&cipher_ctx,ciphertext + outlen1,&outlen2);
    EVP_CIPHER_CTX_cleanup(&cipher_ctx);

    mutils_write_blob(blob,outlen1 + outlen2,ciphertext);

    /* calculate HMAC-SHA256 */
    sha256 = EVP_sha256();
    HMAC_CTX_init(&hmac_ctx);
    HMAC_Init(&hmac_ctx,hmac_key_32,32,sha256);
    HMAC_Update(&hmac_ctx,blob->data,blob->length);
    HMAC_Final(&hmac_ctx,hmac_sha256,&hmac_len);
    HMAC_CTX_cleanup(&hmac_ctx);

    mutils_write_blob(blob,hmac_len,hmac_sha256);
    output = (unsigned char *)malloc(blob->length * sizeof(unsigned char));
    CHECK_MALLOC(output);

    memcpy(output,blob->data,blob->length);
    *outdata_len = blob->length;
ExitProcessing:
    if (ci)
    {
        free_rncryptor_info(ci);
    }

    if (blob)
    {
        mutils_destroy_blob(blob);
    }
    if (ciphertext)
    {
        (void) free((char *)ciphertext);
    }
    return(output);
}

unsigned char *rncryptorc_decrypt_data_with_password(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const char *password,
        int password_length,
        int *outdata_len,
        char *errbuf,
        int errbuf_len)
{
    MutilsBlob
        *blob = NULL;

    RNCryptorInfo
        *ci = NULL;

    int
        rc,
        outlen1=0,
        outlen2=0;

    EVP_CIPHER_CTX
        cipher_ctx;

    unsigned char
        *outdata = NULL;

    if (errbuf_len <= 0)
    {
        log_err("ERROR:Invalid errbuf len %d",errbuf_len);
        goto ExitProcessing;
    }

    if (indata == NULL)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Input data is NULL");
        goto ExitProcessing;
    }
    if (password == NULL || *password == '\0')
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Password is NULL");
        goto ExitProcessing;
    }
    if (password_length <= 0)
    {
        (void)snprintf(errbuf,errbuf_len-1,
                "Invalid password length %d",password_length);
        goto ExitProcessing;
    }

    *outdata_len = 0;

    /* convert input data to our blob */
    blob = mutils_data_to_blob((unsigned char *)indata,indata_len);
    CHECK_MALLOC(blob);

    /* decode */
    log_debug("%s:%d - Decoding ..",MCFL);
    ci = decode_encrypted_blob(blob);
    if (!ci)
    {
        goto ExitProcessing;
    }
    ci->options = 0x01;

    rc = verify_rncryptor_format(ci->version,ci->options);
    if (rc != SUCCESS)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Unknown RNCryptor Data Format");
        goto ExitProcessing;
    }
    log_debug("%s:%d - Decoded version 0x%02x options 0x%02x",
            MCFL,
            ci->version,
            ci->options);

    log_debug("%s:%d - Verifying HMAC-SHA256 digest",MCFL);
    /* very hmac */
    if (verify_hmac(ci,password,password_length) != SUCCESS)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Could not verify HMAC");
        goto ExitProcessing;
    }
    log_debug("%s:%d - HMAC verified",MCFL);

    /* Derive cipher key from password using encr salt and iteration as per RFC2898 */
    log_debug("%s:%d - Deriving Cipher key with salt, iteration %d",
            MCFL,
            kdf_iter);
    rc = PKCS5_PBKDF2_HMAC_SHA1(password,password_length,
            ci->encryption_salt,
            sizeof(ci->encryption_salt),
            ci->kdf_iter,
            sizeof(ci->encr_key),
            ci->encr_key); /* ci->encr_key is returend */
    if (rc != 1)
    {
        log_err("ERROR: Could not derive key from password with encr salt and iter");
        goto ExitProcessing;
    }
    log_debug("%s:%d - Encryption key derived",MCFL);

    /* decrypt */
    outdata = (unsigned char *)malloc(ci->cipher_text_length *sizeof(unsigned char));
    CHECK_MALLOC(outdata);

    log_debug("%s:%d - Decrypting..",MCFL);
    EVP_DecryptInit(&cipher_ctx,EVP_aes_256_cbc(),ci->encr_key,ci->iv);
    EVP_DecryptUpdate(&cipher_ctx,outdata,&outlen1,ci->cipher_text,
            ci->cipher_text_length);
    EVP_DecryptFinal(&cipher_ctx,outdata + outlen1,&outlen2);
    EVP_CIPHER_CTX_cleanup(&cipher_ctx);

    *outdata_len = outlen1 + outlen2;
    log_debug("%s:%d - Done decrypting, output length %d bytes",MCFL,*outdata_len);
ExitProcessing:
    if (ci)
    {
        free_rncryptor_info(ci);
    }
    if (blob)
    {
        mutils_destroy_blob(blob);
    }

    return(outdata);
}

unsigned char *rncryptorc_decrypt_data_with_key(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const unsigned char *encr_key,
        const unsigned char *hmac_key,
        int *outdata_len,
        char *errbuf,
        int errbuf_len)
{
    MutilsBlob
        *blob = NULL;

    RNCryptorInfo
        *ci = NULL;

    int
        outlen1=0,
        outlen2=0;

    EVP_CIPHER_CTX
        cipher_ctx;

    unsigned char
        *outdata = NULL;

    if (errbuf_len <= 0)
    {
        log_err("ERROR:Invalid errbuf len %d",errbuf_len);
        goto ExitProcessing;
    }

    memset(errbuf,0,errbuf_len);

    if (indata == NULL)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "input data is NULL");
        goto ExitProcessing;
    }
    if (encr_key == NULL)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Encryption key is NULL");
        goto ExitProcessing;
    }
    if (hmac_key == NULL)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "HMAC key is NULL");
        goto ExitProcessing;
    }

    *outdata_len = 0;

    /* convert input data to our blob */
    blob = mutils_data_to_blob((unsigned char *)indata,indata_len);
    CHECK_MALLOC(blob);

    /* decode */
    ci = decode_encrypted_blob(blob);
    if (!ci)
    {
        goto ExitProcessing;
    }
    log_debug("Decoded successfully");

    /*
    ** copy the keys to our data structure, this way we don't have
    ** to change code for decryptiion
    */
    memcpy(ci->encr_key,encr_key,32);
    memcpy(ci->hmac_key,hmac_key,32);
    /*
    ** pass password as NULL and length of password as 0 because we don't
    ** have to derive HMAC key
    */
    if (verify_hmac(ci,NULL,0) != SUCCESS)
    {
        (void)snprintf(errbuf,errbuf_len-1,"%s",
                "Could not verify HMAC");
        goto ExitProcessing;
    }
    log_debug("HMAC verified");


    /* malloc for returned data */
    outdata = (unsigned char *)malloc(ci->cipher_text_length *sizeof(unsigned char));
    CHECK_MALLOC(outdata);

    /* decrypt */
    EVP_DecryptInit(&cipher_ctx,EVP_aes_256_cbc(),ci->encr_key,ci->iv);
    EVP_DecryptUpdate(&cipher_ctx,outdata,&outlen1,ci->cipher_text,
            ci->cipher_text_length);
    EVP_DecryptFinal(&cipher_ctx,outdata + outlen1,&outlen2);
    EVP_CIPHER_CTX_cleanup(&cipher_ctx);

    *outdata_len = outlen1 + outlen2;

ExitProcessing:
    if (ci)
    {
        free_rncryptor_info(ci);
    }
    if (blob)
    {
        mutils_destroy_blob(blob);
    }

    return(outdata);
}


unsigned char *rncryptorc_read_file(const char *path,int *length)
{
    unsigned char
        *content;

    MutilsBlob
        *blob;

    *length = 0;
    blob = mutils_file_to_blob(path);
    if (blob)
    {
        content = (unsigned char *)malloc(blob->length * sizeof(unsigned char));
        memcpy(content,blob->data,blob->length);
        *length = blob->length;
        mutils_destroy_blob(blob);
        return content;
    }
    return(NULL);
}

void show_example_usage(const char *prog,const char *arg1,const char *arg2)
{
        (void) fprintf(stderr,
"\nRNCryptor-C v%s\n"
"\nAn example program of RNCryptor-C. RNCryptor-C is a C implementation\n"
"of RNCryptor's data format spec v%d\n\n",
    RNCRYPTORC_VERSION_S,
    RNCRYPTOR_DATA_FORMAT_VERSION);
(void) fprintf(stderr, "  RNCryptor:%s\n", RNCRYPTOR_URL);
(void) fprintf(stderr, "RNCryptor-C:%s\n\n", RNCRYPTORC_URL);

        (void) fprintf(stderr,"Usage: %s <%s> <%s>\n\n",
                prog,arg1,arg2);

        (void) fprintf(stderr,"Set the password with env variable RNCPASS\n");
        (void) fprintf(stderr,
"Exmaple:\n"
"In Linux/Unix:\n"
"  RNCPASS=\"secret\";export RNCPASS\n"
"In Windows:\n"
"  SET RNCPASS=secret\n");
}

void show_example_usage_with_key(const char *prog,const char *arg1,const char *arg2)
{
        (void) fprintf(stderr,
"\nRNCryptor-C v%s\n"
"\nAn example program of RNCryptor-C. RNCryptor-C is a C implementation\n"
"of RNCryptor's data format spec v%d\n\n",
    RNCRYPTORC_VERSION_S,
    RNCRYPTOR_DATA_FORMAT_VERSION);

(void) fprintf(stderr, "  RNCryptor:%s\n", RNCRYPTOR_URL);
(void) fprintf(stderr, "RNCryptor-C:%s\n\n", RNCRYPTORC_URL);

        (void) fprintf(stderr,"Usage: %s <encrkeyfile.bin> \\\n  <hmackeyfile.bin> <%s> <%s>\n\n",
                prog,arg1,arg2);
        (void) fprintf(stderr,"Note: keys must be 32 bytes long\n");
}


int rncryptorc_write_file(const char *outfile_path,const unsigned char *data,int data_len)
{
    int
        rc = FAILURE;

    FILE
        *ofp = NULL;
    if (outfile_path == NULL || *outfile_path == '\0')
    {
        (void) fprintf(stderr,"File path can not be NULL\n");
        rc = FAILURE;
        goto ExitProcessing;
    }
    if (data == NULL || data_len <= 0)
    {
        (void) fprintf(stderr,"Invalid data\n");
        rc = FAILURE;
        goto ExitProcessing;
    }
    if (*outfile_path == '-')
    {
        ofp = stdout;
    }
    else
    {
        ofp = fopen(outfile_path,"wb");
        if (ofp == NULL)
        {
            (void) fprintf(stderr,"Could not create file %s\n",outfile_path);
            rc = FAILURE;
            goto ExitProcessing;
        }
    }
    fwrite(data,sizeof(char),data_len,ofp);
    rc = SUCCESS;

ExitProcessing:
    if (ofp && ofp != stdout)
    {
        (void)fclose(ofp);
    }
    return(rc);
}

/* return SUCCESS or FAILURE */
int verify_rncryptor_format(unsigned char version,unsigned char options)
{
    if (version == 0x03 && (options == 0x00 || options == 0x01))
    {
        return SUCCESS;
    }
    return FAILURE;
}
