CURL=-lcurl

default: local

local: auth_tcpcrypt.o

auth_tcpcrypt.o:
	apxs2 -I . -cia apache2_module.c apache2_module_init.c crypto.c tcpcrypt_session.c

clean:
	rm -f *.o *.so *.slo *.lo *.la *.pyc
	rm -rf .libs/

restart:
	sudo /etc/init.d/apache2 restart

test_http_tcpcrypt_auth.o:
	gcc -g -Wall -Werror -lssl -std=c99 -I`pwd` -Icontrib -I../tcpcrypt/code/user ${CURL} -o test/test_http_tcpcrypt_auth test/test_http_tcpcrypt_auth.c test/header.c contrib/curl_http_kv_parser.c http_tcpcrypt_auth.c tcpcrypt_session.c

test_build: test_http_tcpcrypt_auth.o

test: test_build
	test/test_http_tcpcrypt_auth

pake:
	gcc -DTCPCRYPT_HTTP_MAIN -I. -g -lssl -o tcpcrypt_http_pake pake.c test/test_pake.c



