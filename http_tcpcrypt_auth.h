#ifndef HTTP_TCPCRYPT_AUTH_H
#define HTTP_TCPCRYPT_AUTH_H

/* Writes the 32-byte hex string
       MD5(user ":" realm ":" pw)
   at `ha1`.
 */
void make_ha1(char * restrict ha1, 
              const char *user, 
              const char *realm, 
              const char *pw);

#endif // HTTP_TCPCRYPT_AUTH_H
