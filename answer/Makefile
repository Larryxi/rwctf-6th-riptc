.PHONY: all clean

TARGET = poc

CFLAGS = -c -I./include
LDFLAGS = -Wall -static

all: main.o util.o setup.o usched.o
	$(CC) $(LDFLAGS) $^ -o $(TARGET)
main.o: src/main.c include/util.h
	$(CC) $(CFLAGS) $<
util.o: src/util.c include/util.h
	$(CC) $(CFLAGS) $<
setup.o: src/setup.c include/setup.h include/util.h
	$(CC) $(CFLAGS) $<
usched.o: src/usched.c include/usched.h include/util.h
	$(CC) $(CFLAGS) $<
clean:
	rm *.o $(TARGET)
