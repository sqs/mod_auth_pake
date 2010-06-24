default: local

local: auth_tcpcrypt.o

auth_tcpcrypt.o:
	apxs2 -I . -cia apache2_module.c apache2_module_init.c crypto.c tcpcrypt_session.c

clean:
	rm -f *.o *.so *.slo *.lo *.la
	rm -rf .libs/

restart:
	sudo /etc/init.d/apache2 restart

