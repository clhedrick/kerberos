all: ccselect_nfs.so

ccselect_nfs.so: ccselect_nfs.c
	gcc -fPIC -fno-stack-protector -c ccselect_nfs.c
	ld -x --shared -o ccselect_nfs.so ccselect_nfs.o -lkrb5 -lk5crypto -lcom_err -lkrb5support -lc
	echo no version newer than 2.2.5 should show, failure OK
	-readelf -a ccselect_nfs.so | grep GLIBC_ | grep -v 2.2.5

installans: all
	install --owner=root --group=root --mode=0755 ccselect_nfs.so /config/kerberos-ansible/kerberos-files/copy/usr/lib/ccselect_nfs.so

install: all
	install --owner=root --group=root --mode=0755 ccselect_nfs.so /usr/lib/ccselect_nfs.so
      


