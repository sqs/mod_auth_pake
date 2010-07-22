#include "test_acctmgmt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include "test_http_tcpcrypt_auth.h"

static char *strdup(const char *str)
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

int parse_link_header(char *hdr, char **url, char **rel) {
    *rel = NULL;
    *url = NULL;

    while (isspace(hdr[0])) hdr++;
    
    if (hdr[0] != '<') return 0;
    hdr++;

    char *url_end = strchr(hdr, '>');
    url_end[0] = '\0';
    *url = hdr;
    
    hdr += strlen(*url) + 1 + strlen("; rel=\"");
    char *rel_end = strchr(hdr, '"');
    rel_end[0] = '\0';
    *rel = hdr;

    return 1;
}

void test_parses_acctmgmt_link() {
    char *hdr = strdup(" <http://example.com/amcd.json>; rel=\"acct-mgmt\" ");
    char *url, *rel;
    
    assert(parse_link_header(hdr, &url, &rel));
    assert(url);
    assert(rel);
    assert(strcmp("http://example.com/amcd.json", url) == 0);
    assert(strcmp("acct-mgmt", rel) == 0);
}

void test_advertises_acctmgmt_realm() {
    struct http_request req;
    struct http_response res;
    char *link_hdr, *link_url, *link_rel;

    req.url = TEST_PROTECTED_URL;
    do_http_request(&req, &res);
    link_hdr = header_val(&res, "Link:");

    /* want something like:
       Link: <http://site.com/meta/amcd.json>; rel="acct-mgmt"
     */
    assert(link_hdr);
    assert(parse_link_header(link_hdr, &link_url, &link_rel));
    assert(link_url);
    assert(strcmp("acct-mgmt", link_rel) == 0);
}

void test_am_status_inactive() {
    struct http_request req;
    struct http_response res;
    char *am_hdr;

    req.url = TEST_PROTECTED_URL;
    do_http_request(&req, &res);
    am_hdr = header_val(&res, "X-Account-Management-Status:");

    /* want something like:
       X-Account-Management-Status: none
     */
    assert(am_hdr);
    assert(strncmp(" none", am_hdr, strlen(" none")) == 0);
}

