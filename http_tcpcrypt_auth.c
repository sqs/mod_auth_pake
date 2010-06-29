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
