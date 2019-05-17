all: pam_reg_cc.so

pam_reg_cc.so: pam_reg_cc.c 
	gcc -fPIC -fno-stack-protector -c pam_reg_cc.c
	gcc -fPIC -fno-stack-protector -c ../common/ccacheutil.c
	ld -x --shared -o pam_reg_cc.so ccacheutil.o pam_reg_cc.o -lkrb5 -lk5crypto -lcom_err -lkrb5support -lc -lpam
	echo no version newer than 2.2.5 should show, failure OK
	-readelf -a pam_reg_cc.so | grep GLIBC_ | grep -v 2.2.5

installans: all
	install --owner=root --group=root --mode=0755 pam_reg_cc.so /config/kerberos-ansible/kerberos-files/copy/usr/lib64/security/pam_reg_cc.so
	install --owner=root --group=root --mode=0644 pam_reg_cc.8 /config/kerberos-ansible/kerberos-files/copy/usr/share/man/man8/pam_reg_cc.8

install: all
	cp pam_reg_cc.so /usr/lib64/security
	cp pam_reg_cc.8 /usr/share/man/man8

installu14: all
	cp pam_reg_cc.so /lib/x86_64-linux-gnu/security/pam_reg_cc.so
	cp pam_reg_cc.8 /usr/share/man/man8
	cp rukerb /usr/share/pam-configs/rukerb



