#ifndef MUTILS_H
#define MUTILS_H

/*
**  A stripped down version from my libmutils library
** muquit@muquit.com May-27-2015
*/

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
#ifndef O_RDONLY    /* prevent multiple inclusion on lame systems (from
vile)*/
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

#if defined(PATH_MAX)
#define MUTILS_PATH_MAX       PATH_MAX
#elif defined(_POSIX_PATH_MAX)
#define MUTILS_PATH_MAX       _POSIX_PATH_MAX
#else
#define MUTILS_PATH_MAX  4098
#endif

#if !defined(O_BINARY)
#define O_BINARY  0x00
#endif

#define MUTILS_TRUE   1
#define MUTILS_FALSE  0

#define MUTILS_MAX(a,b) ((a) > (b) ? (a) : (b))
#define MUTILS_MIN(a,b) ((a) > (b) ? (b) : (a))
/* from net-snmp 5.0.6 tools.h */


typedef struct _MutilsBlob
{
    size_t
        length;

    unsigned char
        *data;

    size_t
        offset,
        size;
}MutilsBlob;


#define MUTILS_CFL  __FILE__,__LINE__
#define MCFL             __FILE__,__LINE__
#define MJL              __LINE__

/*
** Adapted from some very old ImageMagick code, long long time ago!
*/
void mutils_rewind_blob(MutilsBlob *blob);
MutilsBlob *mutils_clone_blobinfo(MutilsBlob *blob_info);
MutilsBlob *mutils_allocate_blob(int data_len);
MutilsBlob *mutils_file_to_blob(const char *filename);
MutilsBlob *mutils_data_to_blob(unsigned char *data,int data_len);
void     mutils_detach_blob(MutilsBlob *blob_info);
void     mutils_destroy_blob(MutilsBlob *blob);
void     mutils_msb_order_long(char *p,const size_t length);
void     mutils_msb_order_short(char *p,const size_t length);

int     mutils_read_blob(MutilsBlob *blob_info,const size_t length,
                                void *data);
int            mutils_read_blob_byte(MutilsBlob *blob);
unsigned long  mutils_read_blob_lsb_long(MutilsBlob *blob_info);
unsigned short mutils_read_blob_lsb_short(MutilsBlob *blob);
unsigned long  mutils_read_blob_msb_long(MutilsBlob *blob,int *err_no);
unsigned short mutils_read_blob_msb_short(MutilsBlob *blob,int *err_no);
char           *mutils_read_blob_string(MutilsBlob *blob,char *string,int slen);
int     mutils_size_blob(MutilsBlob *blob);
int     mutils_tell_blob(MutilsBlob *blob);

int     mutils_write_blob(MutilsBlob *blob,const size_t length,const void *data);
size_t  mutils_write_blob_byte(MutilsBlob *blob_info,const long value);
int     mutils_write_blob_lsb_long(MutilsBlob *blob,const unsigned long value);
int     mutils_write_blob_lsb_short(MutilsBlob *blob,const unsigned long value);
int     mutils_write_blob_msb_long(MutilsBlob *blob,const unsigned long value);
int     mutils_write_blob_msb_short(MutilsBlob *blob,const unsigned long value);
size_t  mutils_write_blob_string(MutilsBlob *blob_info,const char *string);

void mutils_hex_print(FILE *fp,unsigned char *bytes,int len);
unsigned char mutils_hex_char_to_bin(char x);
unsigned char *mutils_hex_to_bin(const char *hex_string,int len,int *olen);

#endif /* MUTILS_H */
