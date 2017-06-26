all:: mkhomedird kmkhomedir pam_kmkhomedir.so

mkhomedird: mkhomedird.c
	gcc -DHAVE_CONFIG_H  -I/usr/include/krb5  -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -O2 -Wall -Wcast-align -Wshadow -Wmissing-prototypes -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wmissing-prototypes -Wreturn-type -Wmissing-braces -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -pthread -c mkhomedird.c
	gcc  -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -g -o mkhomedird mkhomedird.o -lkrb5 -lk5crypto -lcom_err -lkrb5support  -lkeyutils -lresolv  -ldl

kmkhomedir: pam_kmkhomedir.c
	gcc -DHAVE_CONFIG_H  -I/usr/include/krb5  -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -O2 -Wall -Wcast-align -Wshadow -Wmissing-prototypes -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wmissing-prototypes -Wreturn-type -Wmissing-braces -Wparentheses -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -pthread -c pam_kmkhomedir.c
	gcc  -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -o kmkhomedir pam_kmkhomedir.o -lkrb5 -lk5crypto -lcom_err -lkrb5support  -lkeyutils -lresolv  -ldl

pam_kmkhomedir.so: pam_kmkhomedir.c
	gcc -fPIC -fno-stack-protector -DPAM -DHAVE_CONFIG_H  -I/usr/include/krb5  -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -O2 -Wall -Wcast-align -Wshadow -Wmissing-prototypes -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wmissing-prototypes -Wreturn-type -Wmissing-braces -Wparentheses -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -pthread -c pam_kmkhomedir.c -o pam_kmkhomedir.o
	ld -x --shared -o pam_kmkhomedir.so pam_kmkhomedir.o -lkrb5 -lk5crypto -lcom_err -lkrb5support  -lkeyutils -lresolv  -ldl

clean::
	rm mkhomedird.o mkhomedird 

install:: all
	cp pam_kmkhomedir.so /lib64/security
	cp pam_kmkhomedir.8 /usr/share/man/man8
