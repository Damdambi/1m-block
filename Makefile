all: 1m-block

1m-block: 1m-block.o set_wrapper.o
	g++ -o 1m-block 1m-block.o set_wrapper.o -lnetfilter_queue
    
set_wrapper.o: set_wrapper.cpp
	g++ -c -o set_wrapper.o set_wrapper.cpp

1m-block.o: 1m-block.c
	gcc -c -o 1m-block.o 1m-block.c
    
clean:
	rm *.o 1m-block
