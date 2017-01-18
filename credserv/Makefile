all:: credserv

credserv: credserv.c
	gcc -DHAVE_CONFIG_H  -I/usr/include/krb5  -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -O2 -Wall -Wcast-align -Wshadow -Wmissing-prototypes -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wmissing-prototypes -Wreturn-type -Wmissing-braces -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -pthread -c credserv.c
	gcc  -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -g -o credserv credserv.o -lkrb5 -lk5crypto -lcom_err -lkrb5support  -lkeyutils -lresolv  -ldl

clean::
	rm credserv.o credserv

install::

