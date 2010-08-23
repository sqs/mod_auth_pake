SRC=test_http_pake_auth.c ../http_header.c ../contrib/curl_http_kv_parser.c
OBJ=$(SRC:.c=.o)
OUT=test_http_pake_auth
INCLUDES=-I. -I.. -I../contrib
CFLAGS+=-std=c99
LIBS+=-lcurl -lpake

.PHONY: clean test

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
