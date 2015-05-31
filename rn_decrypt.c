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
        *password = NULL,
        *encrypted_file = NULL,
        *decrypted_file = NULL;

    unsigned char
        *outdata = NULL;

    int
        outdata_len = 0,
        rc;

    char
        errbuf[BUFSIZ];

    if (argc != 3)
    {
        show_example_usage(argv[0],"file.enc","file.plain");
        return(1);
    }
    password = getenv("RNCPASS");
    if (!password)
    {
        (void) fprintf(stderr,"ERROR: set the password with env variable RNCPASS\n");
        return(1);
    }

    encrypted_file = argv[1];
    decrypted_file = argv[2];

    memset(errbuf,0,sizeof(errbuf));
    rncryptorc_set_debug(1);
    outdata = rncryptorc_decrypt_file_with_password(encrypted_file,
            RNCRYPTOR3_KDF_ITER,
            password,strlen(password),
            &outdata_len,
            errbuf,sizeof(errbuf)-1);
    if (outdata)
    {
        rc = rncryptorc_write_file(decrypted_file,outdata,outdata_len);
        (void) free((char *)outdata);
        if (rc == SUCCESS)
        {
            if (*decrypted_file != '-')
                (void) fprintf(stderr,"%s:%d - Decrypted to %s\n",MCFL,decrypted_file);
            else
            {
                (void) fflush(stdout);
            }
            return(0);
        }
    }

    return(1);
}
