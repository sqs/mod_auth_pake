#include "http_tcpcrypt_auth.h"
#include <string.h>
#include <openssl/evp.h>


void make_ha1(char * restrict ha1, 
              const char *user,
              const char *realm,
              const char *pw)
{
    EVP_MD_CTX mdctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    EVP_DigestInit(&mdctx, EVP_md5());
    EVP_DigestUpdate(&mdctx, user, strlen(user));
    EVP_DigestUpdate(&mdctx, ":", 1);
    EVP_DigestUpdate(&mdctx, realm, strlen(realm));
    EVP_DigestUpdate(&mdctx, ":", 1);
    EVP_DigestUpdate(&mdctx, pw, strlen(pw));
    EVP_DigestFinal_ex(&mdctx, md, &md_len);
    EVP_MD_CTX_cleanup(&mdctx);
    
    int i;
    for (i=0; i < md_len; ++i) {
        int c = sprintf(ha1, "%02x", md[i]);
        ha1 += c;
    }
}


void make_response(char * restrict resp,
                   const char *ha1,
                   const char *nonce,
                   long sid)
{
    EVP_MD_CTX mdctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    char sid_hex[9]; // 8 hex chars plus NULL
    sprintf(sid_hex, "%lx", sid);

    EVP_DigestInit(&mdctx, EVP_md5());
    EVP_DigestUpdate(&mdctx, ha1, strlen(ha1));
    EVP_DigestUpdate(&mdctx, ":", 1);
    EVP_DigestUpdate(&mdctx, nonce, strlen(nonce));
    EVP_DigestUpdate(&mdctx, ":", 1);
    EVP_DigestUpdate(&mdctx, sid_hex, strlen(sid_hex));
    EVP_DigestFinal_ex(&mdctx, md, &md_len);
    EVP_MD_CTX_cleanup(&mdctx);
    
    int i;
    for (i=0; i < md_len; ++i) {
        int c = sprintf(resp, "%02x", md[i]);
        resp += c;
    }
}
