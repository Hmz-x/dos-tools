# Makefile for building and installing overload DoS tool

CC = gcc
CFLAGS = -Wall -pthread -O2
TARGET = overload
SOURCES = overload.c
OBJ = $(SOURCES:.c=.o)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	@mkdir -p /usr/share/dos-tools
	@cp user_agents.txt /usr/share/dos-tools/user_agents.txt
	@cp dns_servers.txt /usr/share/dos-tools/dns_servers.txt
	@cp $(TARGET) /usr/local/bin/$(TARGET)
	@echo "Installation complete!"

clean:
	@rm -f $(OBJ) $(TARGET)
	@echo "Clean complete!"
