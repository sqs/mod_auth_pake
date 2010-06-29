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
	gcc -g -Wall -Werror -std=c99 -Icontrib -I../tcpcrypt/code/user ${CURL} -o test/test_http_tcpcrypt_auth test/test_http_tcpcrypt_auth.c  test/parser.c contrib/curl_http_kv_parser.c

test: test_http_tcpcrypt_auth.o
	test/test_http_tcpcrypt_auth
	
