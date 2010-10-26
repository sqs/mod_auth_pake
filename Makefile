export CC=gcc
export CFLAGS=-Wall -Werror -g

export SRC=auth_pake.c http_header.c contrib/curl_http_kv_parser.c
export OBJ=$(SRC:.c=.o)
export INCLUDES=-I. -Icontrib
export LIBS=-lssl -lcrypto -lpake
LDFLAGS=$(LIBS)

.PHONY: test clean restart

.SUFFIXES: .c

default: build

build: $(SRC)
	apxs2 $(INCLUDES) $(LIBS) $(LDFLAGS) -cia -Wc,-g $(SRC)

clean:
	rm -f *.o *.so *.slo *.lo *.la *.pyc
	rm -rf .libs/

buildre: build restart

restart:
	sudo /etc/init.d/apache2 restart

htpake: htpake.c

test:
	$(MAKE) -C test

test_build:
	$(MAKE) -C test build
