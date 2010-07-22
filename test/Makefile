SRC=test_acctmgmt.c test_http_tcpcrypt_auth.c ../http_header.c ../tcpcrypt_session.c ../contrib/curl_http_kv_parser.c
OBJ=$(SRC:.c=.o)
OUT=test_http_tcpcrypt_auth
INCLUDES=-I. -I.. -I../contrib -I/home/sqs/src/pake/src/
CFLAGS+=-std=c99
LIBS+=-lcurl

.PHONY: clean test www

default: test

build: $(OUT)

test: build
	@./$(OUT)

%.o: %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	$(CC) $(LDFLAGS) $(LIBS) -o $@ $(OBJ)

clean:
	rm -f $(OBJ) $(OUT)

www:
	cp -R ../www/* ../www/.well-known /var/www/
