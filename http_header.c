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

static void check_header(struct tcpcrypt_http_header *hdr) {
    /* TODO */
    if (hdr->type == HTTP_AUTHORIZATION) {
        assert(hdr->username && strlen(hdr->username) && hdr->realm && strlen(hdr->realm) &&
               strlen(hdr->X) && strlen(hdr->Y) == 0 && strlen(hdr->respc) &&
               strlen(hdr->resps) == 0);
    } else if (hdr->type == HTTP_AUTHORIZATION_USER) {
        assert(hdr->username && strlen(hdr->username) && !hdr->realm && 
               strlen(hdr->X) == 0 && strlen(hdr->Y) == 0 && 
               strlen(hdr->respc) == 0 && strlen(hdr->resps) == 0);
    } else if (hdr->type == HTTP_WWW_AUTHENTICATE) {
        assert(hdr->username && strlen(hdr->username) && hdr->realm && strlen(hdr->realm) &&
               strlen(hdr->X) == 0 && strlen(hdr->Y) && strlen(hdr->respc) == 0 &&
               strlen(hdr->resps) == 0);
    } else if (hdr->type == HTTP_AUTHENTICATION_INFO) {
        assert(!hdr->username && !hdr->realm && 
               strlen(hdr->X) == 0 && strlen(hdr->Y) == 0 && 
               strlen(hdr->respc) == 0 && strlen(hdr->resps));
    } else {
        assert(NULL);
    }
}

int tcpcrypt_http_header_parse(struct tcpcrypt_http_header *hdr, const char *header_line, enum tcpcrypt_http_auth_header_type type) {
    memset(hdr, 0, sizeof(*hdr));
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
                    strncpy(hdr->respc, content, RESP_LENGTH);
                    assert(hdr->respc);
                } else if (strcmp(value, "resps") == 0) {
                    strncpy(hdr->resps, content, RESP_LENGTH);
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

    /* See what kind of Authorization: header this is. */
    if (hdr->type == HTTP_AUTHORIZATION && hdr->username &&
        !hdr->realm && hdr->X[0] == '\0' && hdr->Y[0] == '\0' &&
        hdr->respc[0] == '\0' && hdr->resps[0] == '\0') {
        hdr->type = HTTP_AUTHORIZATION_USER;
    }

    check_header(hdr);

    return 1;

 err:
    return 0;
}

int tcpcrypt_http_header_stringify(char *header_line, struct tcpcrypt_http_header *hdr, int value_only) {
    /* TODO: use snprintf */
    /* TODO: escape double quotes in quoted vals */

    check_header(hdr);

    if (hdr->type == HTTP_WWW_AUTHENTICATE) {
        sprintf(header_line, "%sTcpcrypt realm=\"%s\" Y=\"%s\" username=\"%s\"", 
                value_only ? "" : "WWW-Authenticate: ", hdr->realm, hdr->Y,
                hdr->username);
    } else if (hdr->type == HTTP_AUTHORIZATION) {
        sprintf(header_line, "%sTcpcrypt X=\"%s\" username=\"%s\" respc=\"%s\" realm=\"%s\"",
                value_only ? "" : "Authorization: ",
                hdr->X, hdr->username, hdr->respc, hdr->realm);
    } else if (hdr->type == HTTP_AUTHORIZATION_USER) {
        sprintf(header_line, "%sTcpcrypt username=\"%s\"", 
                value_only ? "" : "Authorization: ",
                hdr->username);
    } else if (hdr->type == HTTP_AUTHENTICATION_INFO) {
        sprintf(header_line, "%sTcpcrypt resps=\"%s\"", 
                value_only ? "" : "Authentication-Hdr: ", hdr->resps);

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
