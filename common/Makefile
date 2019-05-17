all: test
test:
	gcc -DHAVE_CONFIG_H  -I/usr/include/krb5  -DKRB5_DEPRECATED=1 -DKRB5_PRIVATE  -g -Wall -Wcast-align -Wshadow -Wno-format-zero-length -Woverflow -Wstrict-overflow -Wmissing-format-attribute -Wreturn-type -Wmissing-braces -Wparentheses -Wswitch -Wunused-function -Wunused-label -Wunused-variable -Wunused-value -Wunknown-pragmas -Wsign-compare -Werror=uninitialized -Werror=pointer-arith -Werror=declaration-after-statement -fno-stack-protector -pthread -c ccacheutil.c
	gcc -o test test.c ccacheutil.o

