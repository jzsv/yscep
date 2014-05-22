#
# $Id: Makefile,v 1.0 2003/01/12 13:17:37 jt Exp $
#

BINDIR = /usr/local/bin
MANDIR = /usr/local/man/man8

CC	= gcc
#WITH_DEBUG   = -g
CFLAGS	= -Wall -O $(WITH_DEBUG)-I/home/jz/Software/openssl-1.0.1/include -L/home/jz/Software/openssl-1.0.1/lib

MAN	= sscep.8
PROG	= yscep
OBJS    = main.o sscep.o init.o net.o sceputils.o pkcs7.o ias.o fileutils.o

all: $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS) -lcrypto -lssl -ldl

clean:
	rm -f $(PROG) $(OBJS) $(MAN) core

install:
	./install-sh $(PROG) $(BINDIR)
	./install-sh $(MAN) $(MANDIR)
