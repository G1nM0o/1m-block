TARGET = 1m-block
SRC = main.c

all:
	g++ -o $(TARGET) $(SRC) -lnetfilter_queue

clean:
	rm -f $(TARGET)