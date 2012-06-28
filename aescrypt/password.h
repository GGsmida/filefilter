#ifndef __AESCRYPT_PASSWORD_H__
#define __AESCRYPT_PASSWORD_H__

#define MAX_PASSWD_LEN  1024

typedef enum {UNINIT, DEC, ENC} encryptmode_t;

/*
 * Error codes for read_password function.
 */
#define AESCRYPT_READPWD_FOPEN       -1
#define AESCRYPT_READPWD_FILENO      -2
#define AESCRYPT_READPWD_TCGETATTR   -3
#define AESCRYPT_READPWD_TCSETATTR   -4
#define AESCRYPT_READPWD_FGETC       -5
#define AESCRYPT_READPWD_TOOLONG     -6
#define AESCRYPT_READPWD_NOMATCH     -7

#endif // __AESCRYPT_PASSWORD_H__
