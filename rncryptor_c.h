#ifndef RNCRYPTOR_C_H
#define RNCRYPTOR_C_H 1

/**
  @mainpage

  @section intro Introduction

  A C implementation of Rob Napier's Objective-C library RNCryptor data
  format specificatoin v 3.

    RNCryptor homepage: https://github.com/RNCryptor/RNCryptor
  RNCryptor-C homepage: https://github.com/muquit/RNCryptor-C

 */

/**
 * @file rncryptor_c.h
 * @brief Function Prototypes
 *
 * This file contains the function prototypes for rncryptorc API functions.
 *
 * @author Muhammad Muquit http://www.muquit.com/
 */
#undef SUCCESS
#undef FAILURE

#define MCFL             __FILE__,__LINE__
#define MJL              __LINE__

#define RNCRYPTORC_VERSION_S          "1.01"
#define RNCRYPTOR_DATA_FORMAT_VERSION 0x03
#define RNCRYPTOR3_KDF_ITER           10000

#define RNCRYPTOR_URL  "https://github.com/RNCryptor/RNCryptor"
#define RNCRYPTORC_URL "https://github.com/muquit/RNCryptor-C"

#define SUCCESS 0x00
#define FAILURE 0x01

#include <stdio.h>

#if STDC_HEADERS || HAVE_STRING_H
#include <string.h> /* ANSI string.h and pre-ANSI memory.h might conflict*/
#if !STDC_HEADERS && HAVE_MEMORY_H
#include <memory.h>
#endif
#else
#if  HAVE_STRINGS_H
#include <strings.h>
#endif
#endif


#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#if UNIX
#include <sys/types.h>
#include <sys/stat.h>
#endif

#ifdef WINNT
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <share.h>
#include <direct.h>
#include <Winsock2.h> /* for timeval */
#define ftruncate chsize

#ifdef getcwd
#undef getcwd
#endif
#define getcwd _getcwd

#ifdef snprintf
#undef snprintf
#endif
#define snprintf _snprintf

#endif

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if HAVE_STDLIB_H 
#include <stdlib.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdarg.h>

#if HAVE_FCNTL_H
#ifndef O_RDONLY    /* prevent multiple inclusion on lame systems (from vile)*/
#include <fcntl.h>
#endif
#endif

#if HAVE_MALLOC_H
#include <malloc.h>
#endif


#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef APR_HAVE_LIMITS_H
#include <limits.h>
#else
#if APR_HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* latest documentation: http://localhost:47899/index.html#apis */

/*
**  Turn on/off debug messages. Default is off
**
**  Parameters:
**      d      Debug value. 1 or 0. To print the debug messages to stdout,
**             call the funtion with 1 before calling any API
**
**  Return Values:
**      None
**
**  Side Effects:
**      none
**
**  Comments:
**      Just a Helper function
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
void rncryptorc_set_debug(int d);

/*
**  Encrypt a file with a password. Encryption salt, HMAC salt and IV are 
**  auto generaed
**
**  Parameters:
**     infile_path    Path of the input file, can not be empty
**     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for RNCryptor 
**                    data format sepc v3
**     password       Password for encryption, can not be empty
**     password_len   Length of the password
**     outdata_len    Returns. Length of the returned encrypted data
**     errbuf         Buffer to write error to
**     errbuf_len     Length of errbuf
**
**  Return Values:
**     Pointer to encrypted data on success, NULL on failure
**     In case of failure errbuf will have the error message
**
**  Side Effects:
**     Memory is allocated for returned data. It is caller's responsibility to free it.
**
**  Comments:
**     The encryption is done as per RNCryptor data format specification v3.
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
unsigned char *rncryptorc_encrypt_file_with_password(const char *infile_path,
        int kdf_iter,
        const char *password,
        int password_length,
        int *outdata_len,
        char *errbuf,
        int errbuf_len);

/*
**  Encrypt a file with a encryption key. HMAC key is also requried for
**  creating the HMAC-SHA256 digest. IV is augo generated.
**
**  Parameters:
**     infile_path    Path of the input file. Required.
**     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for RNCryptor 
**                    data format sepc v3
**     encryption_key 32 byte long encryption key. Required.
**     hmac_key       32 byte long HMAC key. Required.
**     outdata_len    Returns. Length of the returned encryped data
**     errbuf         Buffer to write error to
**     errbuf_len     Length of errbuf
**
**  Return Values:
**     Pointer to encyrped data on success, NULL on failure
**     In case of failure errbuf will have the error message
**
**  Side Effects:
**     Memory is allocated for returned data. It is caller's responsibility to free it.
**
**  Comments:
**     The encryption is done as per RNCryptor data format specification v3.
**     It is caller's responsibility to pass valid arguments.
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
unsigned char *rncryptorc_encrypt_file_with_key(const char *infile_path,
        int kdf_iter,
        const unsigned char *encr_key,
        const unsigned char *hmac_key,
        int *outdata_len,
        char *errbuf,
        int errbuf_len);

/*
**  Decrypt a file with a password
**
**  Parameters:
**     infile_path    Path of the file to decrypt. Required
**     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for RNCryptor 
**                    data format sepc v3
**     password       Password for decryption. Requied
**     password_len   Length of the password
**     outdata_len    Returns. Length of the returned decrypted data
**     errbuf         Buffer to write error to
**     errbuf_len     Length of errbuf
**
**  Return Values:
**     Pointer to decrypted data on success, NULL on failure
**     In case of failure, errbuf will have the error message
**
**  Side Effects:
**     Memory is allocated for returned data. It is caller's responsibility to free it.
**
**  Comments:
**    The encryption is done as per RNCryptor data format specification v3.
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
unsigned char *rncryptorc_decrypt_file_with_password(const char *infile_path,
        int kdf_iter,
        const char *password,
        int password_length,
        int *outdata_len,
        char *errbuf,
        int errbuf_len);

/*
**  Decrypt a file with a encryption key. HMAC key is also requried for
**  verifying the HMAC-SHA256 digest
**
**  Parameters:
**     infile_path    Path of the input file. Required.
**     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for RNCryptor 
**                    data format sepc v3
**     encryption_key 32 byte long encryption key. Required.
**     hmac_key       32 byte long HMAC key. Required.
**     outdata_len    Returns. Length of the returned encryped data
**     errbuf         Buffer to write error to
**     errbuf_len     Length of errbuf
**
**  Return Values:
**     Pointer to deccyrped data on success, NULL on failure.
**     In case of failure, errbuf will have the error message
**
**  Side Effects:
**     Memory is allocated for returned data. It is caller's 
**     responsibility to free it.
**
**  Comments:
**    The encryption is done as per RNCryptor data format specification v3.
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
unsigned char *rncryptorc_decrypt_file_with_key(const char *infile_path,
        int kdf_iter,
        const unsigned char *encr_key,
        const unsigned char *hmac_key,
        int *outdata_len,
        char *errbuf,
        int errbuf_len);

/*
**  Encrypt data with a password. Encryption salt, HMAC salt and IV are
**  auto generated.
**
**  Parameters:
**     indata         Pointer to data to encrypt. Required
**     indata_len     Length of the data in bytes
**     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for RNCryptor 
**                    data format sepc v3
**     password       Password for encryption, can not be empty
**     password_len   Length of the password
**     outdata_len    Returns. Length of the returned encryped data
**     errbuf         Buffer to write error to
**     errbuf_len     Length of errbuf
**
**  Return Values:
**     Pointer to encyrped data on success, NULL on failure.
**     In case of failure errbuf will have the error message
**
**  Side Effects:
**     Memory is allocated for returned data. It is caller's responsibility to free it.
**
**  Comments:
**     The encryption is done as per RNCryptor data format specification v3.
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
unsigned char *rncryptorc_encrypt_data_with_password(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const char *password,
        int password_length,
        int *out_data_len,
        char *errbuf,
        int errbuf_len);

/*
**  Encrypt data with a password. Caller will pass encryption salt, hmac
**  salt and iv
**
**  Parameters:
**     indata         Pointer to data to encrypt. Required
**     indata_len     Length of the data in bytes
**     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for RNCryptor
**                    data format sepc v3
**     password       Password for encryption, can not be empty
**     password_len   Length of the password
**     encr_salt_8    8 byte long encryption salt. Required.
**     hmac_salt_8    8 byte long hmac salt. Required.
**     iv_16          16 byte long iv. Required.
**     outdata_len    Returns. Length of the returned encryped data
**     errbuf         Buffer to write error to
**     errbuf_len     Length of errbuf
**
**  Return Values:
**     Pointer to encyrped data on success, NULL on failure.
**     In case of failure errbuf will have the error message
**
**  Side Effects:
**     Memory is allocated for returned data. It is caller's responsibility to free it.
**
**  Comments:
**     The encryption is done as per RNCryptor data format specification v3.
**
**  Development History:
**   muquit@muquit.com May-30-2015 - first cut
*/
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
        int errbuf_len);


/*
**  Encrypt data with a encryption key. HMAC key is also requried for
**  creating the HMAC-SHA256 digest. IV is auto generatd.
**
**  Parameters:
**     indata         Pointer to input data to encrypt. Required.
**     indata_len     Length of the input data in bytes
**     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for 
**                    RNCryptor data format sepc v3
**     encryption_key 32 byte long encryption key. Required.
**     hmac_key       32 byte long HMAC key. Required.
**     outdata_len    Returns. Length of the returned encryped data
**     errbuf         Buffer to write error to
**     errbuf_len     Length of errbuf
**
**  Return Values:
**     Pointer to encyrped data on success, NULL on failure
**     In case of failure errbuf will have the error message
**
**  Side Effects:
**     Memory is allocated for returned data. It is caller's responsibility to free it.
**
**  Comments:
**     The encryption is done as per RNCryptor data format specification v3.
**     It is caller's responsibility to pass valid arguments.
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
unsigned char *rncryptorc_encrypt_data_with_key(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const unsigned char *encryption_key,
        const unsigned char *hmac_key,
        int *out_data_len,
        char *errbuf,
        int errbuf_len);

/*
**  Encrypt data with a encryption key. Caller will pass encryption key, 
**  hmac key and iv
**
**  Parameters:
**     indata         Pointer to input data to encrypt. Required.
**     indata_len     Length of the input data in bytes
**     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for 
**                    RNCryptor data format sepc v3
**     encr_key_32    32 byte long encryption key. Required.
**     hmac_key_32    32 byte long HMAC key. Required.
**     iv_16          16 byte long IV. Requied.
**     outdata_len    Returns. Length of the returned encryped data
**     errbuf         Buffer to write error to
**     errbuf_len     Length of errbuf
**
**  Return Values:
**     Pointer to encyrped data on success, NULL on failure
**     In case of failure errbuf will have the error message
**
**  Side Effects:
**     Memory is allocated for returned data. It is caller's 
**     responsibility to free it.
**
**  Comments:
**     The encryption is done as per RNCryptor data format specification v3.
**
**  Development History:
**   muquit@muquit.com May-30-2015 - first cut
*/
unsigned char *rncryptorc_encrypt_data_with_key_iv(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const unsigned char *encryption_key_32,
        const unsigned char *hmac_key_32,
        const unsigned char *iv_16,
        int *outdata_len,
        char *errbuf,
        int errbuf_len);

/*
**  Decrypt data with a password
**
**  Parameters:
**     indata         Pointer to input data to encrypt. Required.
**  indata_len        Length of the input data in bytes
**     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for RNCryptor 
**                    data format sepc v3
**     password       Password for decryption. Requied
**     password_len   Length of the password
**     outdata_len    Returns. Length of the returned decrypted data
**     errbuf         Buffer to write error to
**     errbuf_len     Length of errbuf
**
**  Return Values:
**     pointer to decrypted data on success, NULL on failure
**     In case of failure, errbuf will have the error message
**
**  Side Effects:
**     Memory is allocated for returned data. It is caller's responsibility to free it.
**
**  Comments:
**    The encryption is done as per RNCryptor data format specification v3.
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
unsigned char *rncryptorc_decrypt_data_with_password(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const char *password,
        int password_length,
        int *out_data_len,
        char *errbuf,
        int errbuf_len);

/*
**  Decrypt a file with a encryption key. HMAC key is also requried for
**  verifying the HMAC-SHA256 digest
**
**  Parameters:
**     indata         Pointer to input data to encrypt. Required.
**  indata_len        Length of the input data in bytes
**     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for RNCryptor 
**                    data format sepc v3
**     encryption_key 32 byte long encryption key. Required.
**     hmac_key       32 byte long HMAC key. Required.
**     outdata_len    Returns. Length of the returned encryped data
**     errbuf         Buffer to write error to
**     errbuf_len     Length of errbuf
**
**  Return Values:
**     Pointer to deccyrped data on success, NULL on failure.
**     In case of failure, errbuf will have the error message.
**
**  Side Effects:
**     Memory is allocated for returned data. It is caller's responsibility to free it.
**
**  Comments:
**    The encryption is done as per RNCryptor data format specification v3.
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
unsigned char *rncryptorc_decrypt_data_with_key(const unsigned char *indata,
        int indata_len,
        int kdf_iter,
        const unsigned char *encr_key,
        const unsigned char *hmac_key,
        int *outdata_len,
        char *errbuf,
        int errbuf_len);

/*
**  Read and return the content of a file
**
**  Parameters:
**      path   Path of the file to read
**      length Length of the data. returns.
**
**  Return Values:
**      pointer to content of file on success, NULL on failure
**
**  Side Effects:
**      Memory is allocated for the returned data, the caller is responsible
**      to free it
**
**  Comments:
**      Just a Helper function
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
unsigned char *rncryptorc_read_file(const char *path,int *length);

/*
**  Write data to a file
**
**  Parameters:
**      outfile_path   Path of the output file
**      data           Pointer to data
**      data_len       Length of data
**
**  Return Values:
**      SUCCESS or FAILURE
**
**  Side Effects:
**      none
**
**  Comments:
**      Just a Helper function
**
**  Development History:
**   muquit@muquit.com May-20-2015 - first cut
*/
int rncryptorc_write_file(const char *outfile_path,const unsigned char *data,int data_len);

/* TODO */
typedef void (*rncryptorc_log_func)(const char *fmt,va_list args);
void rncryptorc_log_error(const char *fmt,...);
void rncryptorc_log_info(const char *fmt,...);
void rncryptorc_log_debug(const char *fmt,...);
/*
** show usage for examples
*/
void show_example_usage(const char *prog,const char *arg1,const char *arg2);
void show_example_usage_with_key(const char *prog,const char *arg1,const char *arg2);

/* returns SUCCESS or FAILURE */
int verify_rncryptor_format(unsigned char version,unsigned char options);

#endif /* RNCRYPTOR_C_H */
