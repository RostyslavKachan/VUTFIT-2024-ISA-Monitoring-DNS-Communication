# Compiler to be used is g++
CPP = g++
# Compiler flags
CXXFLAGS = -Wall -g
# Target executable name
TARGET = dns-monitor
# Source files that make up the project
SRCS = main.cpp
# Object files, які генеруються з source files
OBJS = $(SRCS:.cpp=.o)
# pcap library
LDFLAGS = -lpcap

#making executable file
$(TARGET): $(OBJS)
	$(CPP) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

#making object files
%.o: %.cpp
	$(CPP) $(CXXFLAGS) -c $<

#delete object files and target
clean:
	rm -f $(OBJS) $(TARGET)
