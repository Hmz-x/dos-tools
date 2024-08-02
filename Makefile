# Makefile

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -O2 -pthread

# Libraries
LIBS = -lnet

# Executable names
UDP_EXEC = xi-udp
TCP_EXEC = xi-tcp
OVERLOAD_EXEC = overload

# Source files
UDP_SRC = xi-udp.c
TCP_SRC = xi-tcp.c
OVERLOAD_SRC = overload.c

# Object files
UDP_OBJ = $(UDP_SRC:.c=.o)
TCP_OBJ = $(TCP_SRC:.c=.o)
OVERLOAD_OBJ = $(OVERLOAD_SRC:.c=.o)

# Data files
USER_AGENTS_FILE = user_agents.txt
DNS_SERVERS_FILE = dns_servers.txt

# Data installation directory
DATA_DIR = /usr/share/dos-tools

# Default target
all: $(UDP_EXEC) $(TCP_EXEC) $(OVERLOAD_EXEC)

# Compile xi-udp
$(UDP_EXEC): $(UDP_OBJ)
	$(CC) $(CFLAGS) -o $(UDP_EXEC) $(UDP_OBJ) $(LIBS)

# Compile xi-tcp
$(TCP_EXEC): $(TCP_OBJ)
	$(CC) $(CFLAGS) -o $(TCP_EXEC) $(TCP_OBJ) $(LIBS)

# Compile overload
$(OVERLOAD_EXEC): $(OVERLOAD_OBJ)
	$(CC) $(CFLAGS) -o $(OVERLOAD_EXEC) $(OVERLOAD_OBJ) $(LIBS)

# Rule for compiling C files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(UDP_OBJ) $(TCP_OBJ) $(OVERLOAD_OBJ) $(UDP_EXEC) $(TCP_EXEC) $(OVERLOAD_EXEC)

# Install binaries and data files
install: $(UDP_EXEC) $(TCP_EXEC) $(OVERLOAD_EXEC)
	cp $(UDP_EXEC) /usr/local/bin/
	cp $(TCP_EXEC) /usr/local/bin/
	cp $(OVERLOAD_EXEC) /usr/local/bin/
	mkdir -p $(DATA_DIR)
	cp $(USER_AGENTS_FILE) $(DATA_DIR)/
	cp $(DNS_SERVERS_FILE) $(DATA_DIR)/

# Uninstall binaries and data files
uninstall:
	rm -f /usr/local/bin/$(UDP_EXEC)
	rm -f /usr/local/bin/$(TCP_EXEC)
	rm -f /usr/local/bin/$(OVERLOAD_EXEC)
	rm -rf $(DATA_DIR)
