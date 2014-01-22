# $Id: Makefile 12 2008-11-22 13:45:26Z duck $

# enable this to not look up dst port names on each line
#OPTIONS=-DNO_SERVENT

CC=cc
CFLAGS=-g -Wall -pedantic -ansi $(OPTIONS)
LDFLAGS=-lpcap

SRCS=str.c main.c
OBJS=$(SRCS:S/.c/.o/g)

RM=rm -f
INSTALL=install

PREFIX?=/usr/local
PROG=pfloggerd

program:	$(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LDFLAGS)

.c.o:	$(SRCS)
	$(CC) $(CFLAGS) -c -o $@ $<

install:
	$(INSTALL) $(PROG) $(PREFIX)/bin

clean:
	$(RM) *.core
	$(RM) $(OBJS)
	$(RM) $(PROG)
