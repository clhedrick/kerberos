all: renewd.c
	gcc -DHAVE_CONFIG_H  -I/usr/include/krb5  -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -Wall -Wcast-align -Wshadow -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wreturn-type -Wmissing-braces -Wparentheses -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -pthread -c renewd.c
	gcc  -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -o renewd renewd.o -lkrb5 -lk5crypto -lcom_err -lkrb5support  -lkeyutils -lresolv  -ldl

install:	all	
	cp renewd.service /etc/systemd/system/renewd.service 
	systemctl stop renewd
	cp renewd /usr/sbin/renewd
	systemctl start renewd
	cp renewd.8 /usr/share/man/man8
