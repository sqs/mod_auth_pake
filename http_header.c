#include "http_header.h"
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

int tcpcrypt_http_header_parse(struct tcpcrypt_http_header *hdr, const char *header_line) {
    /* TODO: check whether HTTP header keys are case sensitive */
    static const char *h_www_auth = "WWW-Authenticate:",
                      *h_authorization = "Authorization:",
                      *h_authentication_info = "Authentication-Info:";
    
    /* find header key */
    if (strncmp(h_www_auth, header_line, strlen(h_www_auth)) == 0) {
        hdr->type = HTTP_WWW_AUTHENTICATE;
        header_line += strlen(h_www_auth);
    } else if (strncmp(h_authorization, header_line, strlen(h_authorization)) == 0) {
        hdr->type = HTTP_AUTHORIZATION;
        header_line += strlen(h_authorization);
    } else if (strncmp(h_authentication_info, header_line, strlen(h_authentication_info)) == 0) {
        hdr->type = HTTP_AUTHENTICATION_INFO;
        header_line += strlen(h_authentication_info);
    } else {
        goto err;
    }

    /* skip whitespaces */
    while(*header_line && isspace(*header_line))
        header_line++;
    
    if (strncmp("Tcpcrypt", header_line, strlen("Tcpcrypt")) == 0) {
        header_line += strlen("Tcpcrypt");
        hdr->auth_name = "Tcpcrypt";

        while(1) {
            char value[MAX_VALUE_LENGTH];
            char content[MAX_CONTENT_LENGTH];

            while(*header_line && isspace(*header_line))
                header_line++;

            /* extract a value=content pair */
            if(!get_pair(header_line, value, content, &header_line)) {
                if (strcmp(value, "username") == 0) {
                    hdr->username = strdup(content);
                    assert(hdr->username);
                } else if (strcmp(value, "realm") == 0) {
                    hdr->realm = strdup(content);
                    assert(hdr->realm);
                } else if(strcmp(value, "X") == 0) {
                    hdr->X = strdup(content);
                    assert(hdr->X);
                } else if(strcmp(value, "Y") == 0) {
                    hdr->Y = strdup(content);
                    assert(hdr->Y);
                } else if (strcmp(value, "respc") == 0) {
                    hdr->respc = strdup(content);
                    assert(hdr->respc);
                } else if (strcmp(value, "resps") == 0) {
                    hdr->resps = strdup(content);
                    assert(hdr->resps);
                } else {
                    fprintf(stderr, "unknown kv pair: %s\n", value);
                    /* unknown specifier, ignore it! */
                }
            }
            else
                break; /* we're done here */

            /* pass all additional spaces here */
            while(*header_line && isspace(*header_line))
                header_line++;
            if(',' == *header_line)
                /* allow the list to be comma-separated */
                header_line++;
        }
    } else {
        /* else not for us, get out */
        fprintf(stderr, "no \"Tcpcrypt\" in header=\"%s\"\n", header_line);
        goto err;
    }

    return 1;

 err:
    return 0;
}

int tcpcrypt_http_header_stringify(char *header_line, struct tcpcrypt_http_header *info) {
    return 1;
}

void tcpcrypt_http_header_inspect(struct tcpcrypt_http_header *hdr) {
    printf("header hdr: %s realm=\"%s\"\n", 
           hdr->auth_name,
           hdr->realm /* , TODO more */);
}
