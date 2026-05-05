TARGET = 1m-block
SRC = main.cpp

all:
	g++ -o $(TARGET) $(SRC) -lnetfilter_queue

clean:
	rm -f $(TARGET)
