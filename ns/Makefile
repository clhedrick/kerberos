all: runinns
runinns: runinns.c
	cc -o runinns runinns.c
	chmod u+s runinns

installans: runinns
	install runinns -o root -g root -m 4755 /config/kerberos-ansible/runinns-files/usr/bin
	install create.py -o root -g root -m 755 /config/kerberos-ansible/runinns-files/usr/libexec
	install killns.py -o root -g root -m 755 /config/kerberos-ansible/runinns-files/usr/libexec
