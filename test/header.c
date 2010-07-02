#include "header.h"
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


void parse_header(struct tcpcrypt_http_header *hdr, const char *header_val) {
    int more = 1;

    /* skip initial whitespaces */
    while(*header_val && isspace(*header_val))
        header_val++;
    
    if (strncmp("Tcpcrypt", header_val, strlen("Tcpcrypt")) == 0) {
        header_val += strlen("Tcpcrypt");
        hdr->auth_name = "Tcpcrypt";

        while(more) {
            char value[MAX_VALUE_LENGTH];
            char content[MAX_CONTENT_LENGTH];

            while(*header_val && isspace(*header_val))
                header_val++;

            /* extract a value=content pair */
            if(!get_pair(header_val, value, content, &header_val)) {
                if (strcmp(value, "realm") == 0) {
                    hdr->realm = strdup(content);
                    assert(hdr->realm);
                } else if(strcmp(value, "gBVpi0") == 0) {
                    hdr->gBVpi0 = strdup(content);
                    assert(hdr->gBVpi0);
                } else if(strcmp(value, "gaUpi0") == 0) {
                    hdr->gaUpi0 = strdup(content);
                    assert(hdr->gaUpi0);
                } else if (strcmp(value, "rc") == 0) {
                    hdr->rc = strdup(content);
                    assert(hdr->rc);
                } else if (strcmp(value, "rs") == 0) {
                    hdr->rs = strdup(content);
                    assert(hdr->rs);
                } else {
                    fprintf(stderr, "unknown kv pair: %s\n", value);
                    /* unknown specifier, ignore it! */
                }
            }
            else
                break; /* we're done here */

            /* pass all additional spaces here */
            while(*header_val && isspace(*header_val))
                header_val++;
            if(',' == *header_val)
                /* allow the list to be comma-separated */
                header_val++;
        }
    } else {
        /* else not a digest, get out */
        fprintf(stderr, "no \"Tcpcrypt\" in header=\"%s\"\n", header_val);
        return; /* TODO: error */
    }

    return; /* TODO: return ok */
}

void inspect_header(struct tcpcrypt_http_header *hdr) {
    printf("header hdr: %s realm=\"%s\"\n", 
           hdr->auth_name,
           hdr->realm /* , TODO more */);
}
