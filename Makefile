export CC=gcc
export CFLAGS=-Wall -Werror -g

export SRC=apache2_module.c apache2_module_init.c tcpcrypt_session.c http_header.c contrib/curl_http_kv_parser.c
export OBJ=$(SRC:.c=.o)
export INCLUDES=-I. -Icontrib -I/home/sqs/src/pake/src
export LDFLAGS=-L/home/sqs/src/pake/
export LIBS=-lssl -lpake

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

htpake:
	gcc $(CFLAGS) $(INCLUDES) $(LDFLAGS) $(LIBS) -std=c99 htpake.c -o htpake

test:
	$(MAKE) -C test

test_build:
	$(MAKE) -C test build
