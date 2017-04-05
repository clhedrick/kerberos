pam_reg_cc.so: pam_reg_cc.c
	gcc -fPIC -fno-stack-protector -c pam_reg_cc.c
	ld -x --shared -o pam_reg_cc.so  pam_reg_cc.o -lkeyutils -lkrb5 -lk5crypto -lcom_err -lkrb5support



