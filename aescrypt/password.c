#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h> // getopt
#include <stdlib.h> // malloc
#include <iconv.h> // iconv stuff
#include <langinfo.h> // nl_langinfo
#include <errno.h> // errno
#include <termios.h> // tcgetattr,tcsetattr

#include "password.h"

/*
 *  read_password_error
 *
 *  Returns the description of the error when reading the password.
 */
const char* read_password_error(error)
{
    if (error == AESCRYPT_READPWD_FOPEN)
        return "fopen()";
    if (error == AESCRYPT_READPWD_FILENO)
        return "fileno()";
    if (error == AESCRYPT_READPWD_TCGETATTR)
        return "tcgetattr()";
    if (error == AESCRYPT_READPWD_TCSETATTR)
        return "tcsetattr()";
    if (error == AESCRYPT_READPWD_FGETC)
        return "fgetc()";
    if (error == AESCRYPT_READPWD_TOOLONG)
        return "password too long";
    if (error == AESCRYPT_READPWD_NOMATCH)
        return "passwords don't match";
    return "No valid error code specified!!!";
}

/*
 *  read_password
 *
 *  This function reads at most 'MAX_PASSWD_LEN'-1 characters
 *  from the TTY with echo disabled, putting them in 'buffer'.
 *  'buffer' MUST BE ALREADY ALLOCATED!!!
 *  When mode is ENC the function requests password confirmation.
 *
 *  Return value:
 *    >= 0 the password length (0 if empty password is in input)
 *    < 0 error (return value indicating the specific error)
 */

int read_password(char* buffer, encryptmode_t mode)
{
    struct termios t;                   // Used to set ECHO attribute
    int echo_enabled;                   // Was echo enabled?
    int tty;                            // File descriptor for tty
    FILE* ftty;                         // File for tty
    char pwd_confirm[MAX_PASSWD_LEN+1]; // Used for password confirmation
    int c;                              // Character read from input
    int chars_read;                     // Chars read from input
    char* p;                            // Password buffer pointer
    int i;                              // Loop counter
    int match;                          // Do the two passwords match?

    // Open the tty
    ftty = fopen("/dev/tty", "r+");
    if (ftty == NULL)
    {
        return AESCRYPT_READPWD_FOPEN;
    }
    tty = fileno(ftty);
    if (tty < 0)
    {
        return AESCRYPT_READPWD_FILENO;
    }
 
    // Get the tty attrs
    if (tcgetattr(tty, &t) < 0)
    {
        fclose(ftty);
        return AESCRYPT_READPWD_TCGETATTR;
    }

    // Round 1 - Read the password into buffer
    // (If encoding) Round 2 - read password 2 for confirmation
    for (i = 0; (i == 0) || (i == 1 && mode == ENC); i++)
    {
        // Choose the buffer where to put the password
        if (!i)
        {
            p = buffer;
        }
        else
        {
            p = pwd_confirm;
        }

        // Prompt for password
        if (i)
        {
            fprintf(ftty, "Re-");
        }
        fprintf(ftty, "Enter password: ");
        fflush(ftty);

        // Disable echo if necessary
        if (t.c_lflag & ECHO)
        {
            t.c_lflag &= ~ECHO;
            if (tcsetattr(tty, TCSANOW, &t) < 0)
            {
                // For security reasons, erase the password
                memset(buffer, 0, MAX_PASSWD_LEN+1);
                memset(pwd_confirm, 0, MAX_PASSWD_LEN+1);
                fclose(ftty);
                return AESCRYPT_READPWD_TCSETATTR;
            }
            echo_enabled = 1;
        }
        else
        {
            echo_enabled = 0;
        }

        // Read from input and fill buffer till MAX_PASSWD_LEN chars are read
        chars_read = 0;
        while (((c = fgetc(ftty)) != '\n') && (c != EOF))
        {
            // fill buffer till MAX_PASSWD_LEN
            if (chars_read <= MAX_PASSWD_LEN)
                p[chars_read] = (char) c;
            chars_read++;
        }

        if (chars_read <= MAX_PASSWD_LEN+1)
            p[chars_read] = '\0';

        fprintf(ftty, "\n");

        // Enable echo if disabled above
        if (echo_enabled)
        {
            t.c_lflag |= ECHO;
            if (tcsetattr(tty, TCSANOW, &t) < 0)
            {
                // For security reasons, erase the password
                memset(buffer, 0, MAX_PASSWD_LEN+1);
                memset(pwd_confirm, 0, MAX_PASSWD_LEN+1);
                fclose(ftty);
                return AESCRYPT_READPWD_TCSETATTR;
            }
        }

        // check for EOF error
        if (c == EOF)
        {
            // For security reasons, erase the password
            memset(buffer, 0, MAX_PASSWD_LEN+1);
            memset(pwd_confirm, 0, MAX_PASSWD_LEN+1);
            fclose(ftty);
            return AESCRYPT_READPWD_FGETC;
        }

        // Check chars_read.  The password must be maximum MAX_PASSWD_LEN
        // chars.  If too long an error is returned
        if (chars_read > MAX_PASSWD_LEN)
        {
            // For security reasons, erase the password
            memset(buffer, 0, MAX_PASSWD_LEN+1);
            memset(pwd_confirm, 0, MAX_PASSWD_LEN+1);
            fclose(ftty);
            return AESCRYPT_READPWD_TOOLONG;
        }
    }

    // Close the tty
    fclose(ftty);

    // Password must be compared only when encrypting
    if (mode == ENC)
    {
        // Check if passwords match
        match = strcmp(buffer, pwd_confirm);
        memset(pwd_confirm, 0, MAX_PASSWD_LEN+1);

        if (match != 0)
        {
            // For security reasons, erase the password
            memset(buffer, 0, MAX_PASSWD_LEN+1);
            return AESCRYPT_READPWD_NOMATCH;
        }
    }

    return chars_read;
}

/*
 *  passwd_to_utf16
 *
 *  Convert String to UTF-16LE for windows compatibility
 */
int passwd_to_utf16(char *in_passwd,
                    int length,
                    int max_length,
                    char *out_passwd)
{
    char *ic_outbuf,
         *ic_inbuf;
    iconv_t condesc;
    size_t ic_inbytesleft,
           ic_outbytesleft;

    ic_inbuf = in_passwd;
    ic_inbytesleft = length;
    ic_outbytesleft = max_length;
    ic_outbuf = out_passwd;

    if ((condesc = iconv_open("UTF-16LE", nl_langinfo(CODESET))) ==
        (iconv_t)(-1))
    {
        perror("Error in iconv_open");
        return -1;
    }

    if (iconv(condesc, &ic_inbuf, &ic_inbytesleft, &ic_outbuf, &ic_outbytesleft) == -1)
    {
        switch (errno)
        {
            case E2BIG:
                fprintf(stderr, "Error: password too long\n");
                iconv_close(condesc);
                return -1;
                break;
            default:
                //~ printf("EILSEQ(%d), EINVAL(%d), %d\n", EILSEQ, EINVAL, errno);
                fprintf(stderr,
                        "Error: Invalid or incomplete multibyte sequence\n");
                iconv_close(condesc);
                return -1;
        }
    }
    iconv_close(condesc);
    return (max_length - ic_outbytesleft);
}

