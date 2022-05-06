all:: rdpserv

rdpserv: rdpserv.c
	gcc -I/usr/include/krb5  -g -O2 -Wall -Wcast-align -Wshadow -Wmissing-prototypes -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wmissing-prototypes -Wreturn-type -Wmissing-braces -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -c rdpserv.c
	gcc  -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -g -o rdpserv rdpserv.o -lkrb5 -lk5crypto -lcom_err -lkrb5support -lresolv


