default: local

local: auth_tcpcrypt.o

auth_tcpcrypt.o:
	apxs2 -cia mod_auth_tcpcrypt.c

clean:
	rm -f *.o *.so *.slo *.lo *.la
	rm -rf .libs/

