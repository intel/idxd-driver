# SPDX-License-Identifier: GPL-2.0

CC=gcc
CFLAGS=-I.
DEPS=
OBJ=dmautest_test.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

dmautest_test: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f *.o *~ core dmautest_test
