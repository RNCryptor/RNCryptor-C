/*
**
** Decrypt a RNCryptor Encrypted File, Spec v3
** Specification: https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md
**
**  Development History:
**   - muquit@muquit.com May-19-2015 - first cut
*/
#include "rncryptor_c.h"

int main(int argc,char *argv[])
{
    char
        *encrkey_file = NULL,
        *hmackey_file = NULL,
        *encrypted_file = NULL,
        *decrypted_file = NULL;

    unsigned char
        *encr_key = NULL,
        *hmac_key = NULL,
        *outdata = NULL;

    int
        keysize = 0,
        outdata_len = 0,
        rc;

    char
        errbuf[BUFSIZ];

    if (argc != 5)
    {
        show_example_usage_with_key(argv[0],"file.enc","file.plain");
        return(1);
    }

    encrkey_file = argv[1];
    hmackey_file = argv[2];
    encrypted_file = argv[3];
    decrypted_file = argv[4];

    keysize = 0;
    encr_key = rncryptorc_read_file(encrkey_file,&keysize);
    if (encr_key && keysize == 32)
    {
        (void) fprintf(stderr," Read encryptino key\n");
    }
    else
    {
        (void) fprintf(stderr,"Invalid encryption key\n");
        return(1);
    }
    keysize = 0;
    hmac_key = rncryptorc_read_file(hmackey_file,&keysize);
    if (hmac_key && keysize == 32)
    {
        (void) fprintf(stderr," Read HMAC key\n");
    }
    else
    {
        (void) fprintf(stderr,"Invalid HMAC key\n");
        return(1);
    }


    memset(errbuf,0,sizeof(errbuf));
    outdata = rncryptorc_decrypt_file_with_key(encrypted_file,
            RNCRYPTOR3_KDF_ITER,
            encr_key,hmac_key,
            &outdata_len,
            errbuf,sizeof(errbuf)-1);
    (void)free((char *)encr_key);
    (void)free((char *)hmac_key);
    if (outdata)
    {
        rc = rncryptorc_write_file(decrypted_file,outdata,outdata_len);
        (void)free((char *)outdata);
        if (rc == SUCCESS)
        {
            if (*decrypted_file != '-')
                (void) fprintf(stderr,"Decrypted to %s\n",decrypted_file);
            return(0);
        }
    }

    return(1);
}
