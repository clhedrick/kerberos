all: radius-wrap.c
	gcc -fPIC -shared -o radius-wrap.so radius-wrap.c -ldl -lkrb5 -lk5crypto -lcom_err -lkrb5support 

install: all
	cp radius-wrap.so /usr/libexec/



