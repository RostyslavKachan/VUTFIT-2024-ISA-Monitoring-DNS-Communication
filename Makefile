# Compiler to be used is g++
CC = g++
# Compiler flags
CFLAGS = -Wall -Wextra -g
# Libraries
LIBS = -lpcap
# Command to remove files
RM = rm -f

# Target executable
TARGET = dns-monitor
# Source and object files
SRCS = main.cpp
OBJS = $(SRCS:.cpp=.o)

# Default target, builds the executable
.PHONY: all clean

all: $(TARGET)

# Linking step: creates the final executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

# Compiling object file
$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) -c $(SRCS)

# Clean up build artifacts
clean:
	$(RM) $(OBJS) $(TARGET)