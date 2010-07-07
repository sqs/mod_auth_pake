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

int tcpcrypt_http_header_parse(struct tcpcrypt_http_header *hdr, const char *header_line, enum tcpcrypt_http_auth_header_type type) {
    /* TODO: check whether HTTP header keys are case sensitive */
    
    hdr->type = type;
    
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
                    strncpy(hdr->X, content, MAX_EC_POINT_STRING_LENGTH);
                    assert(hdr->X);
                } else if(strcmp(value, "Y") == 0) {
                    strncpy(hdr->Y, content, MAX_EC_POINT_STRING_LENGTH);
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

int tcpcrypt_http_header_stringify(char *header_line, struct tcpcrypt_http_header *info, int value_only) {
    /* TODO: use snprintf */
    /* TODO: escape double quotes in quoted vals */

    if (info->type == HTTP_WWW_AUTHENTICATE) {
        sprintf(header_line, "%sTcpcrypt realm=\"%s\" Y=\"%s\"", 
                value_only ? "" : "WWW-Authenticate: ", info->realm, info->Y);
    } else if (info->type == HTTP_AUTHORIZATION) {
        sprintf(header_line, "%sTcpcrypt X=\"%s\" username=\"%s\" respc=\"%s\" realm=\"%s\"",
                value_only ? "" : "Authorization: ",
                info->X, info->username, info->respc, info->realm);
    } else if (info->type == HTTP_AUTHENTICATION_INFO) {
        sprintf(header_line, "%sTcpcrypt resps=\"%s\"", 
                value_only ? "" : "Authentication-Info: ", info->resps);

    } else {
        goto err;
    }
    
    return 1;

 err:
    return 0;
}

void tcpcrypt_http_header_inspect(struct tcpcrypt_http_header *hdr) {
    printf("header hdr: %s realm=\"%s\"\n", 
           hdr->auth_name,
           hdr->realm /* , TODO more */);
}

