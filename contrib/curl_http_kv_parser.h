#ifndef CURL_HTTP_KV_PARSER_H
#define CURL_HTTP_KV_PARSER_H


#define MAX_VALUE_LENGTH 256
#define MAX_CONTENT_LENGTH 1024

int get_pair(const char *str, char *value, char *content,
             const char **endptr);

#endif // CURL_HTTP_KV_PARSER_H
