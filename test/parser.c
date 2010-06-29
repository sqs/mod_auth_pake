#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "curl_http_kv_parser.h"

char *strdup(const char *str)
{
  size_t len;
  char *newstr;

  if(!str)
    return (char *)NULL;

  len = strlen(str);

  if(len >= ((size_t)-1) / sizeof(char))
    return (char *)NULL;

  newstr = malloc((len+1)*sizeof(char));
  if(!newstr)
    return (char *)NULL;

  memcpy(newstr,str,(len+1)*sizeof(char));

  return newstr;

}


void parse_auth_chal(struct http_tcpcrypt_auth_chal *chal, const char *header) {
    /* char *v = www_authenticate; /\* save typing *\/ */
    
    /* /\* split into 2 parts: auth_name and kv pairs *\/ */
    /* char *sep = index(v, ' '); /\* space after auth_name *\/ */
    /* char *kvpairs = sep + 1; */

    /* /\* auth_name *\/ */
    /* *sep = '\0'; */
    /* chal->auth_name = v; */

    /* /\* realm *\/ */
    
    int more = 1;

    /* skip initial whitespaces */
    while(*header && isspace(*header))
        header++;
    
    if (strncmp("Tcpcrypt", header, strlen("Tcpcrypt")) == 0) {
        header += strlen("Tcpcrypt");
        chal->auth_name = "Tcpcrypt";

        while(more) {
            char value[MAX_VALUE_LENGTH];
            char content[MAX_CONTENT_LENGTH];

            while(*header && isspace(*header))
                header++;

            /* extract a value=content pair */
            if(!get_pair(header, value, content, &header)) {
                if(strcmp(value, "nonce") == 0) {
                    chal->nonce = strdup(content);
                    assert(chal->nonce);
                }
                else if(strcmp(value, "realm") == 0) {
                    chal->realm = strdup(content);
                    assert(chal->realm);
                }
                else if (strcmp(value, "domain") == 0) {
                    chal->domain = strdup(content);
                    assert(chal->domain);
                }
                else {
                    fprintf(stderr, "unknown kv pair: %s\n", value);
                    /* unknown specifier, ignore it! */
                }
            }
            else
                break; /* we're done here */

            /* pass all additional spaces here */
            while(*header && isspace(*header))
                header++;
            if(',' == *header)
                /* allow the list to be comma-separated */
                header++;
        }

        /* We got this header without a nonce, that's a bad Digest line! */
        if(!chal->nonce)
            return; /* TODO: error */
    } else {
        /* else not a digest, get out */
        fprintf(stderr, "no \"Tcpcrypt\" in header=\"%s\"\n", header);
        return; /* TODO: error */
    }

    return; /* TODO: return ok */
}

void inspect_auth_chal(struct http_tcpcrypt_auth_chal *chal) {
    printf("chal: %s realm=\"%s\", nonce=\"%s\", domain=\"%s\"\n", 
           chal->auth_name,
           chal->realm,
           chal->nonce,
           chal->domain);
}
