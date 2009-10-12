#NSPR_INCLUDE_DIR=`pkg-config --cflags-only-I nspr | sed 's@-I@@')`
#NSPR_LIB_DIR=$(pkg-config --libs-only-L nspr | sed 's@-L@@')  \

# -lplds4 -lplc4 -lnspr4 -ldl -lrt -lsocket -ldl -lm 
LDFLAGS=-Wl,-rpath,/usr/lib/nss -Wl,-rpath,/usr/lib/nspr -Wl,--rpath -Wl,/usr/local/lib -Lini

all:
	cd ini && make
	gcc -Iini -I/usr/include/nss -I/usr/include/nspr -c ff_key3db_dump.c
	gcc  $(LDFLAGS) -o ff_key3db_dump ff_key3db_dump.o  -lnspr4 -lnss3 -lsqlite3 -liniparser
#	gcc -o ff_key3db_dump -I/usr/include/nss -I/usr/include/nspr  $(LDFLAGS) ff_key3db_dump.c

