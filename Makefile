CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -lpcap

# Source files
SOURCES = main.c cshark_functions.c packet_analysis.c utils.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = cshark

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c cshark.h
	$(CC) $(CFLAGS) -c $< -o $@

install:
	sudo apt-get update
	sudo apt-get install -y libpcap-dev

clean:
	rm -f $(TARGET) $(OBJECTS)

test: $(TARGET)
	@echo "Testing C-Shark compilation..."
	@echo "Run './$(TARGET)' to start the packet sniffer"