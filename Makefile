OBJS = arp.o
CC = gcc
CFLAGS = -c -Wall

all: $(OBJS)
	$(CC) $(OBJS) -o arp

whohas.o: arp.c
	$(CC) $(CFLAGS) arp.c

clean:
	rm *.o arp
