default: local

local: auth_tcpcrypt.o

auth_tcpcrypt.o:
	apxs2 -cia apache2_module.c

clean:
	rm -f *.o *.so *.slo *.lo *.la
	rm -rf .libs/

restart:
	sudo /etc/init.d/apache2 restart

