all: krenew-wrap.c
	gcc -fPIC -shared -o krenew-wrap.so krenew-wrap.c -ldl -lkrb5 -lk5crypto -lcom_err -lkrb5support 

install: all
	cp krenew-wrap.so /usr/libexec/
	cp ssh /usr/local/bin



