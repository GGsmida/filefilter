#
# Makefile for aescrypt
# Copyright (C) 2007, 2008
# Paul E. Jones <paulej@packetizer.com>
#
# This software is licensed as "freeware."  Permission to distribute
# this software in source and binary forms is hereby granted without a
# fee.  THIS SOFTWARE IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
# THE AUTHOR SHALL NOT BE HELD LIABLE FOR ANY DAMAGES RESULTING FROM THE
# USE OF THIS SOFTWARE, EITHER DIRECTLY OR INDIRECTLY, INCLUDING, BUT
# NOT LIMITED TO, LOSS OF DATA OR DATA BEING RENDERED INACCURATE.
#

#CFLAGS=-I. -ggdb -D_FILE_OFFSET_BITS=64
CC=gcc
CFLAGS=-D_FILE_OFFSET_BITS=64

aescrypt: aescrypt.o aes.o sha256.o password.o
	$(CC) $(CFLAGS) -o $@ $^

test:
	@$(CC) -DTEST -o sha.test sha256.c
	@./sha.test
	@#rm sha.test
	@$(CC) -DTEST -o aes.test aes.c
	@./aes.test
	@#rm aes.test

testfile: aescrypt
	@echo "testing this 123..." > test.orig.txt
	./aescrypt -e -p "praxis" test.orig.txt
	@cp test.orig.txt.aes test.txt.aes
	./aescrypt -d -p "praxis" test.txt.aes
	cmp test.orig.txt test.txt

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $*.c

install: aescrypt
	install -o root -g root -m 755 aescrypt /usr/bin

uninstall:
	rm -f /usr/bin/aescrypt

clean:
	rm -f *.o aescrypt test* *test
