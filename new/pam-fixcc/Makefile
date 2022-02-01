all: test pam-fixcc.so

pam-fixcc.so: pam-fixcc.c
	gcc -fPIC -fno-stack-protector -c pam-fixcc.c
	ld -x --shared -o pam-fixcc.so pam-fixcc.o -lkrb5 -lk5crypto -lcom_err -lkrb5support -lc -lpam
	echo no version newer than 2.2.5 should show, failure OK
	-readelf -a pam-fixcc.so | grep GLIBC_ | grep -v 2.2.5

test: pam-fixcc.c main.c
	gcc -o test -g pam-fixcc.c main.c -lkrb5 -lk5crypto -lcom_err -lkrb5support -lc


installans: all
	install --owner=root --group=root --mode=0755 pam_reg_cc.so /config/kerberos-ansible/kerberos-files/copy/usr/lib64/security/pam_reg_cc.so
	install --owner=root --group=root --mode=0644 pam_reg_cc.8 /config/kerberos-ansible/kerberos-files/copy/usr/share/man/man8/pam_reg_cc.8

install: all
	cp pam-fixcc.so /usr/lib64/security
	cp pam-fixcc.8 /usr/share/man/man8

installu14: all
	cp pam_reg_cc.so /lib/x86_64-linux-gnu/security/pam_reg_cc.so
	cp pam_reg_cc.8 /usr/share/man/man8
	cp rukerb /usr/share/pam-configs/rukerb



