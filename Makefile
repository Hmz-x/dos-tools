CC = gcc
CFLAGS = -Wall -pthread -O2
TARGET = overload
SRCS = overload.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	mkdir -p /usr/share/dos-tools
	cp user_agents.txt /usr/share/dos-tools/
	cp dns_servers.txt /usr/share/dos-tools/
	cp $(TARGET) /usr/local/bin/$(TARGET)
