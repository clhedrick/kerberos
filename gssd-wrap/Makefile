all: gssd-wrap.c
	gcc -fPIC -shared -o gssd-wrap.so gssd-wrap.c -ldl -lgssapi_krb5

install: all
	cp gssd-wrap.so /usr/libexec/




