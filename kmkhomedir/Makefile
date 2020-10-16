all:: mkhomedird kmkhomedir pam_kmkhomedir.so

# NOTE: mkhomedir_helper.c is taken from linux-pam.org. It's mostly unchanged, but main was removed
# and a couple of other minor changes. The original is kept as mkhomedir_helper.c.orig, so new versions
# can be merged

# zfs is a version that sets the ZFS quota. It has to be built on a system with ZFS and ZFS development
zfs: getquota.c mkhomedird.c
	gcc -c getquota.c
	gcc -DZFS -DHAVE_CONFIG_H  -I/usr/include/krb5 -I/usr/include/libzfs -I/usr/include/libspl -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -O2 -Wall -Wno-unused-result -Wcast-align -Wshadow -Wmissing-prototypes -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wmissing-prototypes -Wreturn-type -Wmissing-braces -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -Wno-suggest-attribute=format  -pthread -c mkhomedird.c
	gcc  -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -g -o mkhomedird mkhomedird.o getquota.o -lkrb5 -lk5crypto -lcom_err -lkrb5support  -lkeyutils -lresolv  -ldl -lzfs

mkhomedird: mkhomedird.c
	gcc -DHAVE_CONFIG_H  -I/usr/include/krb5  -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -O2 -Wall -Wno-unused-result -Wcast-align -Wshadow -Wmissing-prototypes -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wmissing-prototypes -Wreturn-type -Wmissing-braces -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -pthread -c mkhomedird.c
	gcc  -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -g -o mkhomedird mkhomedird.o -lkrb5 -lk5crypto -lcom_err -lkrb5support  -lkeyutils -lresolv  -ldl

kmkhomedir: pam_kmkhomedir.c
	gcc -DHAVE_CONFIG_H  -I/usr/include/krb5  -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -O2 -Wall -Wno-unused-result -Wcast-align -Wshadow -Wmissing-prototypes -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wmissing-prototypes -Wreturn-type -Wmissing-braces -Wparentheses -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -pthread -c pam_kmkhomedir.c
	gcc  -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -o kmkhomedir pam_kmkhomedir.o -lkrb5 -lk5crypto -lcom_err -lkrb5support  -lkeyutils -lresolv  -ldl

pam_kmkhomedir.so: pam_kmkhomedir.c mkhomedir_helper.c
	gcc -fPIC -fno-stack-protector -DPAM -DHAVE_CONFIG_H  -I/usr/include/krb5  -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -O2 -Wall -Wno-unused-result -Wcast-align -Wshadow -Wmissing-prototypes -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wmissing-prototypes -Wreturn-type -Wmissing-braces -Wparentheses -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -pthread -c pam_kmkhomedir.c -o pam_kmkhomedir.o
	gcc -c -fPIC -fno-stack-protector -DPAM mkhomedir_helper.c
# need the -lc to get fstat
	ld -x --shared -o pam_kmkhomedir.so pam_kmkhomedir.o mkhomedir_helper.o -lkrb5 -lk5crypto -lcom_err -lkrb5support  -lkeyutils -lresolv  -ldl -lpam -lc
	echo no version newer than 2.2.5 should show, failure OK
	-readelf -a pam_kmkhomedir.so | grep GLIBC_ | grep -v 2.2.5

clean::
	rm mkhomedird.o mkhomedird 

installans:: all
	install --owner=root --group=root --mode=0755 pam_kmkhomedir.so /config/kerberos-ansible/kerberos-files/copy/usr/lib64/security/pam_kmkhomedir.so
	install --owner=root --group=root --mode=0644 pam_kmkhomedir.8 /config/kerberos-ansible/kerberos-files/copy/usr/share/man/man8/pam_kmkhomedir.8

install:: all
	cp pam_kmkhomedir.so /lib64/security
	cp pam_kmkhomedir.8 /usr/share/man/man8

installu14:: all
	cp pam_kmkhomedir.so /lib/x86_64-linux-gnu/security/
	cp pam_kmkhomedir.8 /usr/share/man/man8
