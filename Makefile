OBJS = whohas.o
CC = gcc
CFLAGS = -c -Wall

all: $(OBJS)
	$(CC) $(OBJS) -o whohas

whohas.o: whohas.c
	$(CC) $(CFLAGS) whohas.c

clean:
	rm *.o whohas
