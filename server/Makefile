	# the compiler: gcc for C program, define as g++ for C++
  	CC=gcc
	DEBUG = -g
	
	
	RM=/bin/rm -f
	MV=/bin/mv -f
  # LOCATION of all Files
	HEADERS = $(shell ls hdr/*.h)
	SOURCES = $(shell ls src/*.c)
	BUILD_LOCATION = build/
  	SOURCE_LOCATION = src/
  # compiler flags:
  #  -g    adds debugging information to the executable file
  #  -Wall turns on most, but not all, compiler warnings
  	CFLAGS = -Wall -c $(DEBUG) -DFLAG
	LFLAGS = -Wall $(DEBUG) -lcrypt -lpthread -lssl -lcrypto
	INC = -I$(HEADERS)
	INCLUDES = -I./hdr/	
  # the build target executable:
    TARGET = $(BUILD_LOCATION)file
  	OBJS = $(SOURCES:.c=.o)
	BIN_DIR = build/
  
#SPLINT
	

  all: $(TARGET)

	$(RM) $(SOURCE_LOCATION)*.o

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LFLAGS) $(LIBS) $(INC)

	$(MV) $(SOURCE_LOCATION)*.o $(BUILD_LOCATION)	

	
  clean: 
	$(RM) $(BUILD_LOCATION)*.*
	$(RM) $(BUILD_LOCATION)*


  security: 
	#splint $(SOURCES) | grep error
	flawfinder $(SOURCES)
