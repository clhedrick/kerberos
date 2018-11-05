all: gssd-wrap.c
	gcc -fPIC -shared -o gssd-wrap.so gssd-wrap.c -ldl -lgssapi_krb5
	echo no version newer than 2.2.5 should show, failure OK
	-readelf -W -a gssd-wrap.so | grep GLIBC_ | grep -v GLIBC_2.2.5

install: all
	cp gssd-wrap.so /usr/libexec/

installans: all
	cp gssd-wrap.so /config/kerberos-ansible/kerberos-files/usr/libexec/gssd-wrap.so


