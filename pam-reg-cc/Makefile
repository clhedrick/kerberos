all: pam_reg_cc.so

pam_reg_cc.so: pam_reg_cc.c
	gcc -fPIC -fno-stack-protector -c pam_reg_cc.c
	ld -x --shared -o pam_reg_cc.so  pam_reg_cc.o -lkeyutils -lkrb5 -lk5crypto -lcom_err -lkrb5support

install: all
	cp pam_reg_cc.so /lib64/security
	cp pam_reg_cc.8 /usr/share/man/man8



