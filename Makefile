#simple makefile to compile ping.c
CC = gcc
CFLAGS = -Wall

all: ping.x

ping.x: ping.o
	$(CC) ping.o -o ping.x

ping.o: ping.c
	$(CC) $(CFLAGS) -c ping.c

clean:
	rm -f *.x *.o
