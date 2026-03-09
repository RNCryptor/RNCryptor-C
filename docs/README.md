# Introduction
A C implementation of Rob Napier’s Objective-C library
@RNCRYPTOR@ data format specification. This implementation supports @SPEC@.
Please note, this is not a port of RNCryptor, rather an implementation
of the RNCryptor’s @SPEC@ in C. I wrote this because I like RNCryptor and I use it in iOS. I
wanted to decrypt RNCryptor’s encrypted files in other platforms but I
found the most implementations of RNCryptor’s specification are
incomplete, buggy and shear lack of documentation. I’m releasing it with
the hope that you’ll find it useful. Suggestions, bug reports are always
welcome. If you have any question, request or suggestion, please enter
it in the @ISSUES@ with appropriate label.

# Requirements

- A C compiler
- @OPENSSL@ header files and libraries

# Features

- Supports RNCryptor’s **password** and **key** based
  encryption/decryption.

- Auto generated or caller generated Encryption salt, HMAC salt and IV

- Custom KDF iteration number. Currently must use RNCryptor’s default
  10,000 (use the define `RNCRYPTOR3_KDF_ITER`) if interoperability with
  RNCryptor’s encrypted files is required.

- Passes @TESTVEC@  Look at @TESTING@ section.

Please look at the @APIS@ section for details.

# Supported Platforms

- Linux/Unix

- MacOS X

- Microsoft Windows

It should compile on any POSIX compliant system. Works on 64 bit
systems.

# Versions

Latest stable version is 1.07. Please look at the @CHANGELOG@ for details on changes.

# Downloads

Please download the latest stable source from @RELEASES@ page

Bug fixes and stable features are merged from dev branch to master
branch every now and then. Clone the repo if you want the latest code.

# How to compile/install

## Linux/Unix/MacOS X

Specify the path of OpenSSL with `configure` to generate the `Makefile`
```bash
$ ./configure --with-openssl=/usr
$ ./configure --with-openssl=/usr/local/ssl
    On macOS openssl installed with homebrew:
$ ./configure --with-openssl=$(brew --prefix openssl@3)
$ make clean
$ make
$ make examples
$ sudo make install
```
The header file `rncryptor_c.h` will be installed in
`/usr/local/include`, the library `librncryptorc.a` will be installed in
`/usr/local/lib`, the example programs will be installed in
`/usr/local/bin`

If you use the library in your code, you must link with openssl
libraries. For testing the code, plese look at the [Testing](#Testing)
section

The example programs are:

- `rn_encrypt` - Encrypts a file with a password

- `rn_encrypt_with_key` - Encrypts a file with an encryption key. Also
  requires a HMAC key for creating HMAC-SHa256 digest

- `run_decrypt` - Decypts a file with a password

- `rn_decrypt_with_key` - Decrypts a file with an encryption key. Also
  requires a HMAC key for verifying HMAC-SHA256 digest.

Please look at the example programs' source to see how the APIs are
used. Look at @EXAMPLES@ sections for usage.

## Microsoft Windows
### With OpenSource mingw-64
This is the method I use now a days.
- Look at @MINGW64@ on how to install it
- Download ZIP archive of @FIREDAEMON_OPENSSL@ and extract it. It does not
require admin priv. Then configure and compile like Linux/macOS:
```bash
./configure --with-openssl=/path/openssl/x64
make clean
make
```

### With Microsoft Visual Studio
NOTE: I did not use this method for a while, so I'm not sure if the process
is still the same.

- Microsoft Visual Studio 2010 and 2013 (can be downloaded from
  microsoft). Make sure to run the appropriate batch file before
  starting compiling. For example run `vsvars32.bat` for VS 2010.

- @OPENSSL@ libraries and header files. Look at
  `INSTALL.32` that comes with OpenSSL on how to compile and install
  OpenSSL. `Makefile.nmake` expects it to be installed at `c:\openssl`

Open a command shell and type:

    c:\> nmake -f Makefile.nmake
    c:\> name -f Makefile.nmake examples

The static library `rncryptorc.lib` and example programs will be
created.

If you use the library in your code, you must link with openssl
libraries.

The example programs are:

- `run_encrypt.exe`

- `rn_encrypt_with_key.exe`

- `rn_decrypt.exe`

- `rn_decrypt_with_key.exe`

Please look at the example programs' source to see how the APIs are
used. Look at @EXAMPLES@ sections for usage.

# Testing

- Requires ruby and minitest ruby gem
- Simple sanity test (requires ruby 2), run in unix:

```bash
➤ make test_simple
>> Compiling example programs ...
<done>
>> Starting tests ...
ruby tests/test.rb
Run options: --seed 45980

# Running:

DECRYPT WITH PASSWORD: PASSED
.ENCRYPT WITH KEY: PASSED
.DECRYPT WITH KEY: PASSED
.ENCRYPT WITH PASSWORD: PASSED
.DECRYPT WITH PASSWORD AGAIN: PASSED
.DECRYPT TEXTFILE WITH PASSWORD: PASSED
..

Finished in 0.593609s, 11.7923 runs/s, 15.1615 assertions/s.

7 runs, 9 assertions, 0 failures, 0 errors, 0 skips
<done>
```
- Test @TESTVEC@  v3.

In Linux/Unix/MacOS X, to generate test code, compile and run, type:
```
    $ make test
```
In Windows, to compile the test code and run, type:
```
    c:\> nmake -f Makefile.nmake test
    Microsoft (R) Program Maintenance Utility Version 10.00.30319.01
    Copyright (C) Microsoft Corporation.  All rights reserved.

            cl /DWINNT /DWIN32 /DHAVE_MALLOC_H /DHAVE_STRING_H /DHAVE_FCNTL_H /DHAVE_CTYPE_H /DHAVE_STDLIB_H /DHAVE_OPENSSL /I. /Ic:/openssl/include /Ox /W3 /wd4996 /nologo tests/test_with_test_vectors.c rncryptorc.lib c:/openssl/lib/libeay32.lib c:/openssl/lib/ssleay32.lib ws2_32.lib shell32.lib advapi32.lib user32.lib gdi32.lib winmm.lib comdlg32.lib comctl32.lib /Fetests/test_with_test_vectors.exe test_with_test_vectors.c
            tests\test_with_test_vectors.exe

    Verify v3_kdf
     One byte: PASSED
     Short password: PASSED
     Passphrase: PASSED
     Long passphrase: PASSED
     Multibyte: PASSED
     Mixed language: PASSED
    Verify v3_password
     All fields empty or zero (with one-byte password): PASSED
     One byte: PASSED
     Exactly one block: PASSED
     More than one block: PASSED
     Multibyte password: PASSED
     Longer text and password: PASSED
    Verify v3_key
     All fields empty or zero: PASSED
     One byte: PASSED
     Exactly one block: PASSED
     More than one block: PASSED
```
# RNCryptor Data Formats

I am depicting RNCryptor’s data format v3 here little more clearly for
myself.

These are only for me, please look the [RNCryptor’s Official Data Format
Specification](https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md)
if you need to implement it in some other language.

## Data format for Password based encryption
```
      0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    | v | o |       Encryption Salt         |      HMAC Salt        /
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    /       |                       IV                              /
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    /       |          Ciphter Text. variable length                /
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |                               HMAC-SHA256                     |
    |                                                               |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

       v = version : 1 Byte (0x03)
       o = options : 1 Byte (0x01)
    encryption salt: 8 Bytes
          HMAC Salt: 8 Bytes
                 IV: 16 Bytes
        Cipher Text: Variable Length
        HMAC-SHA256: 32 Bytes
```
## Data format for Key based encryption
```
      0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    | v | o |                       IV                              /
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    /       |        cipher text. variable length                   /
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    |                           HMAC-SHA256                         |
    |                                                               |
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

       v = version : 1 Byte (0x03)
       o = options : 1 Byte (0x00)
                 IV: 16 Bytes
        Cipher Text: Variable Length
        HMAC-SHA256: 32 Bytes
```
# APIs

The header file @HEADER@ has all the APIs fully documented.

<table>
<caption>RNCryptor-C APIs</caption>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">Function Name</th>
<th style="text-align: left;">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_encrypt_file_with_password">rncryptorc_encrypt_file_with_password()</a></p></td>
<td style="text-align: left;"><p>Encrypt a file with a password.
Encryption salt, HMAC salt and IV are auto generated.</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_encrypt_file_with_key">rncryptorc_encrypt_file_with_key()</a></p></td>
<td style="text-align: left;"><p>Encrypt a file with a key. Caller will
pass Encryption key and HMAC key. IV is auto generated</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_decrypt_file_with_password">rncryptorc_decrypt_file_with_password()</a></p></td>
<td style="text-align: left;"><p>Decrypt a file with a password</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_decrypt_file_with_key">rncryptorc_decrypt_file_with_key()</a></p></td>
<td style="text-align: left;"><p>Decrypt a file with a key. Caller will
pass Encryption key and HMAC key</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_encrypt_data_with_password">rncryptorc_encrypt_data_with_password()</a></p></td>
<td style="text-align: left;"><p>Encrypt data with a password.
Encryption salt, HMAC salt and IV are auto generated</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_encrypt_data_with_password_with_salts_and_iv">rncryptorc_encrypt_data_with_password_with_salts_and_iv</a></p></td>
<td style="text-align: left;"><p>Encrypt data with a password. Caller
Will pass Encryption salt, HMAC salt and IV</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_encrypt_data_with_key">rncryptorc_encrypt_data_with_key()</a></p></td>
<td style="text-align: left;"><p>Encrypt data with a key. Caller will
pass Encryption key and HMAC key. IV is auto generated</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_encrypt_data_with_key_iv">rncryptorc_encrypt_data_with_key_iv()</a></p></td>
<td style="text-align: left;"><p>Encrypt data with a key. Caller will
pass Encryption key, HMAC key and IV</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_decrypt_data_with_password">rncryptorc_decrypt_data_with_password()</a></p></td>
<td style="text-align: left;"><p>Decrypt data with a password</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_decrypt_data_with_key">rncryptorc_decrypt_data_with_key()</a></p></td>
<td style="text-align: left;"><p>Decrypt data with a key. Caller will
pass Encryption key and HMAC key</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_read_file">rncryptorc_read_file()</a></p></td>
<td style="text-align: left;"><p>Read and return the content of a
file</p></td>
</tr>
<tr>
<td style="text-align: left;"><p><a
href="#rncryptorc_write_file">rncryptorc_write_file()</a></p></td>
<td style="text-align: left;"><p>Write data to a file</p></td>
</tr>
</tbody>
</table>

    #include "rncryptor_c.h"

    /*
    **  Encrypt a file with a password. Encryption salt, HMAC salt and IV are auto generaed
    **
    **  Parameters:
    **     infile_path    Path of the input file, can not be empty
    **     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for RNCryptor
    **                    data format sepc v3
    **     password       Password for encryption, can not be empty
    **     password_len   Length of the password
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
    **  creating the HMAC-SHA256 digest. IV is auto generated.
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
    **     Pointer to decrypted data on success, NULL on failure.
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
            int errbuf_len)

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
    **     Memory is allocated for returned data. It is caller's responsibility to free it.
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
            int errbuf_len)

    /*
    **  Encrypt data with a password. Encryption salt, HMAC salt and IV are auto generated.
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
            int errbuf_len)

    /*
    **  Encrypt data with a password. Caller will pass encryption salt, hmac salt and iv
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
            int errbuf_len)

    /*
    **  Encrypt data with a encryption key. HMAC key is also requried for
    **  creating the HMAC-SHA256 digest. IV is auto generated.
    **
    **  Parameters:
    **     indata         Pointer to input data to encrypt. Required.
    **     indata_len     Length of the input data in bytes
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
    unsigned char *rncryptorc_encrypt_data_with_key(const unsigned char *indata,
            int indata_len,
            int kdf_iter,
            const unsigned char *encryption_key,
            const unsigned char *hmac_key,
            int *out_data_len,
            char *errbuf,
            int errbuf_len)

    /*
    **  Encrypt data with a encryption key. Caller will pass encryption key, hmac key and iv
    **
    **  Parameters:
    **     indata         Pointer to input data to encrypt. Required.
    **     indata_len     Length of the input data in bytes
    **     kdf_iter       PBKDF2 iterations. Must Pass RNCRYPTOR3_KDF_ITER for RNCryptor
    **                    data format sepc v3
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
    **     Memory is allocated for returned data. It is caller's responsibility to free it.
    **
    **  Comments:
    **     The encryption is done as per RNCryptor data format specification v3.
    **     It is caller's responsibility to pass valid arguments.
    **
    **  Development History:
    **   muquit@muquit.com May-30-2015 - first cut
    */
    unsigned char *rncryptorc_encrypt_data_with_key_iv(const unsigned char *indata,
            int indata_len,
            int kdf_iter,
            const unsigned char *encr_key_32,
            const unsigned char *hmac_key_32,
            const unsigned char *iv_16,
            int *outdata_len,
            char *errbuf,
            int errbuf_len)

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
            int errbuf_len)

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
            int errbuf_len)

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
    int rncryptorc_write_file(const char *outfile_path,const unsigned char *data,int data_len)

    /*
    **  Turn on/off debug messages. Default is off
    **
    **  Parameters:
    **      d      Debug value. 1 or 0. To print the debug messages to stdout,
    **             call the function with 1 before calling any API
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
    void rncryptorc_set_debug(int d)

# Example Programs

If output file is specified as `-`, the data will be written to stdout.

- **rn\_encrypt** - Encrypt a file with a password

```bash
$ rn_encrypt
RNCryptor-C v1.07

An example program of RNCryptor-C. RNCryptor-C is a C implementation
of RNCryptor's data format spec v3
  RNCryptor:https://github.com/RNCryptor/RNCryptor
RNCryptor-C:https://github.com/RNCryptor/RNCryptor-C

Usage: rn_encrypt <file.plain> <file.enc>

Set the password with env variable RNCPASS
Exmaple:
In Linux/Unix:
  RNCPASS="secret";export RNCPASS
In Windows:
  SET RNCPASS=secret
```

Please Note: When using environment variables to set sensitive values 
like passwords to command line tools, there are a few implications to keep 
in mind. The variable is visible to any process running as the same user 
via `env`, `printenv`, or `/proc/<pid>/environ`, and is inherited by all child 
processes for the duration of the session. The most immediate risk is 
shell history;  the password can be recorded in plaintext in 
`~/.bash_history`. This can be mitigated by setting `HISTCONTROL=ignorespace` in 
`~/.bashrc` (I use bash as my shell) which causes any command that starts with a leading 
space to be silently omitted from history e.g.
`<space>export RNCPASS='secret'`.
I usually use a dedicated terminal window exclusively for this purpose 
and I do not run anything else in that terminal.

- **rn\_encrypt\_with\_key** - Encrypt a file with a, encryption key.
  HMAC key also has to be specified for creating HMAC-SHA256 digest. The
  keys must be 32 bytes long.
```bash
$ rn_encrypt_with_key
RNCryptor-C v1.07

An example program of RNCryptor-C. RNCryptor-C is a C implementation
of RNCryptor's data format spec v3

  RNCryptor:https://github.com/RNCryptor/RNCryptor
RNCryptor-C:https://github.com/RNCryptor/RNCryptor-C

Usage: rn_encrypt_with_key <encrkeyfile.bin> \
  <hmackeyfile.bin> <file.plain> <file.enc>

Note: keys must be 32 bytes long
```

- **rn\_decrypt** - Decrypt a file with a password
```bash
$ rn_decrypt
RNCryptor-C v1.07

An example program of RNCryptor-C. RNCryptor-C is a C implementation
of RNCryptor's data format spec v3

  RNCryptor:https://github.com/RNCryptor/RNCryptor
RNCryptor-C:https://github.com/RNCryptor/RNCryptor-C

Usage: rn_decrypt <file.enc> <file.plain>

Set the password with env variable RNCPASS
Exmaple:
In Linux/Unix:
  RNCPASS="secret";export RNCPASS
In Windows:
  SET RNCPASS=secret
```
- **rn\_decrypt\_with\_key** - Decrypt a file win encryption key. HMAC
  key also has to be specified for verifying the HMAC-SHA256 digest. The
  keys must be 32 bytes long.

**Example**:

The file `test/image.enc` is a JPEG image encrypted on iOS with
passsword `test`. To decrypt the file, set the password with environment
variable **RNCPASS**
```bash
$  RNCPASS="test"; export RNCPASS
$ ./rn_decrypt test/imge.inc image.jpg
libcryptorc: rncryptor_c.c:143 - input data size 617650 bytes
libcryptorc: rncryptor_c.c:908 - Decoding ..
libcryptorc: rncryptor_c.c:339 - Cipher text length 617584
libcryptorc: rncryptor_c.c:925 - Decoded version 0x03 options 0x01
libcryptorc: rncryptor_c.c:929 - Verifying HMAC-SHA256 digest
libcryptorc: rncryptor_c.c:935 - HMAC verified
libcryptorc: rncryptor_c.c:939 - Deriving Cipher key with salt, iteration 10000
libcryptorc: rncryptor_c.c:952 - Encryption key derived
libcryptorc: rncryptor_c.c:958 - Decrypting..
libcryptorc: rncryptor_c.c:966 - Done decrypting, output length 617568 bytes
rn_decrypt.c:57 - Decrypted to image.jpg
```
In Windows, when setting the password from command line, do not use any
quotes around it. Type `SET RNCPASS=secret` and NOT
`SET RNCPASS="secret"`

Write the output to stdout:

- On MacOS X, write the image to stdout and display using preview
```
    $ ./rn_decrypt test/image.inc - | open -a preview -f
```
- On Linux, write the image to stdout and display using
  [ImageMagick](http://www.imagemagick.org)'s display program
```bash
$ ./rn_decrypt test/image.inc - | display -
libcryptorc: rncryptor_c.c:143 - input data size 617650 bytes
libcryptorc: rncryptor_c.c:908 - Decoding ..
libcryptorc: rncryptor_c.c:339 - Cipher text length 617584
libcryptorc: rncryptor_c.c:925 - Decoded version 0x03 options 0x01
libcryptorc: rncryptor_c.c:929 - Verifying HMAC-SHA256 digest
libcryptorc: rncryptor_c.c:935 - HMAC verified
libcryptorc: rncryptor_c.c:939 - Deriving Cipher key with salt, iteration 10000
libcryptorc: rncryptor_c.c:952 - Encryption key derived
libcryptorc: rncryptor_c.c:958 - Decrypting..
libcryptorc: rncryptor_c.c:966 - Done decrypting, output length 617568 bytes
```
- **rn\_decrypt\_with\_key** - Dncrypt a file with a encryption key.
  HMAC key also has to be specified for verifying the HMAC-SHA256
  digest. The keys must be 32 bytes long
```bash
$ rn_decrypt_with_key
RNCryptor-C v1.01

An example program of RNCryptor-C. RNCryptor-C is a C implementation
of RNCryptor's data format spec v3

  RNCryptor:https://github.com/RNCryptor/RNCryptor
RNCryptor-C:https://github.com/muquit/RNCryptor-C

Usage: rn_decrypt_with_key <encrkeyfile.bin> \
  <hmackeyfile.bin> <file.enc> <file.plain>

Note: keys must be 32 bytes long
```
**Example**:
```bash
$./rn_decrypt_with_key tests/encrkey.bin tests/hmackey.bin \
  tests/test_withkey.enc - 2>/dev/null
this is a test
```
The encryption and hmac keys are generated with openssl:
```bash
$ openssl rand 32 -out tests/encrkeyfile.bin
$ openssl rand 32 -out tests/hmackey.bin
```
# FAQ

1.  **How big are the encrypted output size than the plain text?**

RNCryptor’s data format v3 uses cipher type AES-256-CBC (AES encryption
with 256 bytes long key in CBC mode). In CBC mode, input must have a
lenght multiple of block size, therefore input will be padded if
necessary.

The encrypted output length can be determined by the following formula:

- For password based encryption
```bash
output_size = header_size + ciphertext_size + hamc_size
  header_size = 34
   block_size = 16
ciphertext_size = plaintext_size + block_size - (plaintext_size % block_size)
```
If a plaintext size is say 12 bytes:
```bash
ciphertext_size = 12 + 16 - (12 % 16)
                = 12 + 16 - 12
                = 16
```
Note the padding of 4 bytes
```bash
output_size = 34 + 16 + 32
            = 82 bytes
```
# License

The MIT License (MIT)

Copyright (c) 2015-2026 Muhammad Muquit (<https://www.muquit.com/>)

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

