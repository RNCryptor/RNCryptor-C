/*
**
** Encrypt a file using RNCryptor, Spec v3
** Specification: https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md
**
**  Development History:
**   - muquit@muquit.com May-19-2015 - first cut
*/
#include "rncryptor_c.h"

int main(int argc,char *argv[])
{
    char
        *password = NULL,
        *encrypted_file = NULL,
        *plain_file = NULL;

    int
        rc;

    char
        errbuf[BUFSIZ];

    unsigned char
        *outdata = NULL;

    int 
        outdata_len = 0;

    if (argc != 3)
    {
        show_example_usage(argv[0],"file.plain","file.enc");
        return(1);
    }
    password = getenv("RNCPASS");
    if (!password)
    {
        (void) fprintf(stderr,"ERROR: set the password with env variable RNCPASS\n");
        return(1);
    }

    plain_file = argv[1];
    encrypted_file = argv[2];

    memset(errbuf,0,sizeof(errbuf));
    rncryptorc_set_debug(1);
    outdata = rncryptorc_encrypt_file_with_password(plain_file,
            RNCRYPTOR3_KDF_ITER,
            password,strlen(password),
            &outdata_len,
            errbuf,
            sizeof(errbuf)-1);
    if (outdata)
    {
        rc = rncryptorc_write_file(encrypted_file,outdata,outdata_len);
        (void)free((char *)outdata);
        if (rc == SUCCESS)
        {
            (void) fprintf(stderr,"Encrypted file: %s\n",encrypted_file);
            return(0);
        }
    }
    else
    {
        (void) fprintf(stderr,"ERROR: %s\n",errbuf);
        return(1);
    }

    return(0);
}
