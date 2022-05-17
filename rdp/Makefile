all:: rdpserv krdp

rdpserv: rdpserv.c
	gcc -I/usr/include/krb5  -g -O2 -Wall -Wcast-align -Wshadow -Wmissing-prototypes -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wmissing-prototypes -Wreturn-type -Wmissing-braces -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -c rdpserv.c
	gcc  -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -g -o rdpserv rdpserv.o -lkrb5 -lk5crypto -lcom_err -lkrb5support -lresolv

krdp: krdp.c	
	gcc  -Wno-unused-result -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -o krdp krdp.c -lkrb5 -lk5crypto -lcom_err -lkrb5support -lresolv  -ldl 

	gcc -fPIC -fno-stack-protector -DPAM -DHAVE_CONFIG_H  -I/usr/include/krb5 -g -O2 -Wall -Wno-unused-result -c krdp.c -o pam_krdp.o
	ld -x --shared -o pam_krdp.so pam_krdp.o -lkrb5 -lk5crypto -lcom_err -lkrb5support -ldl -lc
	cp pam_krdp.so /usr/lib64/security/pam_krdp.so
#	echo no version newer than 2.2.5 should show. failure OK
#	-readelf -a pam_krdp.so | grep GLIBC_ | grep -v 2.2.5
