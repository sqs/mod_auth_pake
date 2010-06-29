/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_http_kv_parser.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

/*
 * Return 0 on success and then the buffers are filled in fine.
 *
 * Non-zero means failure to parse.
 */
int get_pair(const char *str, char *value, char *content,
                    const char **endptr)
{
  int c;
  int starts_with_quote = 0;
  int escape = 0;

  for(c=MAX_VALUE_LENGTH-1; (*str && (*str != '=') && c--); )
    *value++ = *str++;
  *value=0;

  if('=' != *str++)
    /* eek, no match */
    return 1;

  if('\"' == *str) {
    /* this starts with a quote so it must end with one as well! */
    str++;
    starts_with_quote = 1;
  }

  for(c=MAX_CONTENT_LENGTH-1; *str && c--; str++) {
    switch(*str) {
    case '\\':
      if(!escape) {
        /* possibly the start of an escaped quote */
        escape = 1;
        *content++ = '\\'; /* even though this is an escape character, we still
                              store it as-is in the target buffer */
        continue;
      }
      break;
    case ',':
      if(!starts_with_quote) {
        /* this signals the end of the content if we didn't get a starting quote
           and then we do "sloppy" parsing */
        c=0; /* the end */
        continue;
      }
      break;
    case '\r':
    case '\n':
      /* end of string */
      c=0;
      continue;
    case '\"':
      if(!escape && starts_with_quote) {
        /* end of string */
        c=0;
        continue;
      }
      break;
    }
    escape = 0;
    *content++ = *str;
  }
  *content=0;

  *endptr = str;

  return 0; /* all is fine! */
}

