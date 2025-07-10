# Compiler
CC = gcc

# Source files
SRCS = main.c http.c

# Output executable
TARGET = server

# OpenSSL paths
OPENSSL_DIR = /opt/homebrew/opt/openssl@3
CFLAGS = -I$(OPENSSL_DIR)/include
LDFLAGS = -L$(OPENSSL_DIR)/lib -lssl -lcrypto

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SRCS)
	$(CC) $(SRCS) -o $(TARGET) $(CFLAGS) $(LDFLAGS)

# Clean up build files
clean:
	rm -f $(TARGET)

