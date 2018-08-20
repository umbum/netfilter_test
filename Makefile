CC = g++
LDLIBS = -lnetfilter_queue

OBJECTS = nfq_test.o protoparse.o
HEADERS = protoparse.h
TARGET = nfq_test

$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS) $(LDLIBS)

%.o: %.cpp $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $< 

clean:
	rm -f $(OBJECTS) $(TARGET)

new:
	$(MAKE) clean
	$(MAKE)