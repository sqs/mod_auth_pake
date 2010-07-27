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

static int check_header(struct pake_http_header *hdr) {
    if (hdr->type == PAKE_HTTP_AUTHORIZATION_STAGE2) {
        return hdr->username && strlen(hdr->username) && hdr->realm && strlen(hdr->realm) &&
            strlen(hdr->X) && strlen(hdr->Y) == 0 && strlen(hdr->respc) &&
            strlen(hdr->resps) == 0;
    } else if (hdr->type == PAKE_HTTP_AUTHORIZATION_STAGE1) {
        return hdr->username && strlen(hdr->username) && hdr->realm && strlen(hdr->realm) && 
            strlen(hdr->X) == 0 && strlen(hdr->Y) == 0 && 
            strlen(hdr->respc) == 0 && strlen(hdr->resps) == 0;
    } else if (hdr->type == PAKE_HTTP_WWW_AUTHENTICATE_STAGE1) {
        return !hdr->username && hdr->realm && strlen(hdr->realm) &&
            strlen(hdr->X) == 0 && strlen(hdr->Y) == 0 && strlen(hdr->respc) == 0 &&
            strlen(hdr->resps) == 0;
    } else if (hdr->type == PAKE_HTTP_WWW_AUTHENTICATE_STAGE2) {
        assert(!hdr->username);
        assert(hdr->realm); assert(strlen(hdr->realm));
        assert(strlen(hdr->X) == 0); assert(strlen(hdr->Y));
        assert(strlen(hdr->respc) == 0); assert(strlen(hdr->resps) == 0);

        return !hdr->username && hdr->realm && strlen(hdr->realm) &&
            strlen(hdr->X) == 0 && strlen(hdr->Y) && strlen(hdr->respc) == 0 &&
            strlen(hdr->resps) == 0;
    } else if (hdr->type == PAKE_HTTP_AUTHENTICATION_INFO) {
        return !hdr->username && !hdr->realm && 
            strlen(hdr->X) == 0 && strlen(hdr->Y) == 0 && 
            strlen(hdr->respc) == 0 && strlen(hdr->resps);
    } else {
        return 0;
    }
}

int pake_http_header_parse(struct pake_http_header *hdr, const char *header_line, enum pake_http_auth_header_type_http type) {
    pake_http_header_clear(hdr);
    
    /* skip whitespaces */
    while(*header_line && isspace(*header_line))
        header_line++;
    
    /* TODO(sqs): should be case insensitive */
    if (strncmp("PAKE", header_line, strlen("PAKE")) == 0) {
        header_line += strlen("PAKE");
        hdr->auth_name = "PAKE";

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
        fprintf(stderr, "no \"Pake\" in header=\"%s\"\n", header_line);
        goto err;
    }

    /* See what kind of Authorization: header this is. */
    if (type == HTTP_WWW_AUTHENTICATE) {
        if (hdr->Y[0] == '\0') {
            hdr->type = PAKE_HTTP_WWW_AUTHENTICATE_STAGE1;
        } else {
            hdr->type = PAKE_HTTP_WWW_AUTHENTICATE_STAGE2;
        }
    } else if (type == HTTP_AUTHORIZATION) {
        if (hdr->username && hdr->realm && hdr->X[0] == '\0' &&
            hdr->Y[0] == '\0' && hdr->respc[0] == '\0' && 
            hdr->resps[0] == '\0') {
            hdr->type = PAKE_HTTP_AUTHORIZATION_STAGE1;
        } else {
            hdr->type = PAKE_HTTP_AUTHORIZATION_STAGE2;
        }
    } else if (type == HTTP_AUTHENTICATION_INFO) {
        hdr->type = PAKE_HTTP_AUTHENTICATION_INFO;
    }

    if (!check_header(hdr)) goto err;

    return 1;

 err:
    return 0;
}

int pake_http_header_stringify(char *header_line, struct pake_http_header *hdr, int value_only) {
    /* TODO: use snprintf */
    /* TODO: escape double quotes in quoted vals */

    if (!check_header(hdr)) goto err;

    if (hdr->type == PAKE_HTTP_WWW_AUTHENTICATE_STAGE1) {
        sprintf(header_line, "%sPAKE realm=\"%s\"", 
                value_only ? "" : "WWW-Authenticate: ", hdr->realm);
    } else if (hdr->type == PAKE_HTTP_WWW_AUTHENTICATE_STAGE2) {
        sprintf(header_line, "%sPAKE realm=\"%s\" Y=\"%s\"", 
                value_only ? "" : "WWW-Authenticate: ", hdr->realm, hdr->Y);
    } else if (hdr->type == PAKE_HTTP_AUTHORIZATION_STAGE2) {
        sprintf(header_line, "%sPAKE X=\"%s\" username=\"%s\" respc=\"%s\" realm=\"%s\"",
                value_only ? "" : "Authorization: ",
                hdr->X, hdr->username, hdr->respc, hdr->realm);
    } else if (hdr->type == PAKE_HTTP_AUTHORIZATION_STAGE1) {
        sprintf(header_line, "%sPAKE username=\"%s\" realm=\"%s\"", 
                value_only ? "" : "Authorization: ",
                hdr->username, hdr->realm);
    } else if (hdr->type == PAKE_HTTP_AUTHENTICATION_INFO) {
        sprintf(header_line, "%sPAKE resps=\"%s\"", 
                value_only ? "" : "Authentication-Info: ", hdr->resps);
    } else {
        goto err;
    }
    
    return 1;

 err:
    return 0;
}

void pake_http_header_clear(struct pake_http_header *hdr) {
    memset(hdr, 0, sizeof(*hdr));
}

void pake_http_header_inspect(struct pake_http_header *hdr) {
    printf("header hdr: %s realm=\"%s\"\n", 
           hdr->auth_name,
           hdr->realm /* , TODO more */);
}
