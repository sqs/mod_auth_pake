#ifndef HTTP_TCPCRYPT_AUTH_H
#define HTTP_TCPCRYPT_AUTH_H

/* Writes the 32-byte hex string
       MD5(user ":" realm ":" pw)
   at `ha1`, with no terminating NULL.
 */
void make_ha1(char * restrict ha1, 
              const char *user, 
              const char *realm, 
              const char *pw);

/* Writes the 32-byte hex string
       MD5(HA1 ":" nonce ":" sid)
   at `reponse`, with no terminating NULL.
 */
void make_response(char * restrict response,
                   const char *ha1,
                   const char *nonce,
                   long sid);

#endif // HTTP_TCPCRYPT_AUTH_H
