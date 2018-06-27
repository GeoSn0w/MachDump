CC = gcc
TARGET = MachDump

all : $(TARGET)

$(TARGET) : macho_dump.c
	$(CC) macho_dump.c -o $(TARGET)

clean :
	rm -rf $(TARGET)
