all: krenew-wrap.c
	gcc -fPIC -shared -o krenew-wrap.so krenew-wrap.c -ldl -lkrb5 -lk5crypto -lcom_err -lkrb5support 
	echo no version newer than 2.2.5 should show, failure OK
	-readelf -W -a krenew-wrap.so | grep GLIBC_ | grep -v GLIBC_2.2.5

install: all
	cp krenew-wrap.so /usr/libexec/
	cp ssh /usr/local/bin
	chmod +x /usr/local/bin/ssh

installu14: all
	mkdir -p /usr/libexec
	cp krenew-wrap.so /usr/libexec/
	cp ssh /usr/local/bin
	chmod +x /usr/local/bin/ssh


