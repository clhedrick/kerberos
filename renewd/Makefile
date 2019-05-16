all: renewd.c
	# -fno-stack-protector because with stack protection it generates code that won't work on Ubuntu 14
	gcc -DHAVE_CONFIG_H  -I/usr/include/krb5  -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -Wall -Wcast-align -Wshadow -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wreturn-type -Wmissing-braces -Wparentheses -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -fno-stack-protector -pthread -c renewd.c
	gcc  -Wl,--enable-new-dtags -Wl,-rpath -Wl,/usr/lib -g -O2  -o renewd renewd.o -lkrb5 -lk5crypto -lcom_err -lkrb5support  -lkeyutils -lresolv  -ldl
	echo no version newer than 2.2.5 should show, failure ok
	-readelf -W -a renewd | grep GLIBC_ | grep -v GLIBC_2.2.5


installans: all
	install renewd.service --owner=root --group=root --mode=644 /config/kerberos-ansible/kerberos-files/copy.CentOS.7/etc/systemd/system/renewd.service
	install renewd.service --owner=root --group=root --mode=644 /config/kerberos-ansible/kerberos-files/copy.SLES.12/etc/systemd/system/renewd.service
	install renewd.service --owner=root --group=root --mode=644 /config/kerberos-ansible/kerberos-files/copy.Ubuntu.16/etc/systemd/system/renewd.service
	install renewd.service --owner=root --group=root --mode=644 /config/kerberos-ansible/kerberos-files/copy.Ubuntu.18/etc/systemd/system/renewd.service
	install renewd --owner=root --group=root --mode=755 /config/kerberos-ansible/kerberos-files/usr/sbin/renewd
	install renewd.8 --owner=root --group=root --mode=644 /config/kerberos-ansible/kerberos-files/copy/usr/share/man/man8/renewd.8

install:	all	
	cp renewd.service /etc/systemd/system/renewd.service 
	systemctl stop renewd
	cp renewd /usr/sbin/renewd
	systemctl start renewd
	cp renewd.8 /usr/share/man/man8

installu14:	all
	-service renewd stop
	cp renewd /usr/sbin/renewd
	-service renewd start
	cp renewd.8 /usr/share/man/man8
	cp renewd.initd /etc/init.d/renewd
