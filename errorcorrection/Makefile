all:	ecd2 

rnd.o: rnd.c
	gcc -Wall -O3 -c rnd.c

ecd2.o: ecd2.c errcorrect.h
	gcc -Wall -O3 -c ecd2.c

ecd2: ecd2.o rnd.o 
	gcc -lm -Wall -O3 -o ecd2 rnd.o ecd2.o

clean:
	rm -f *.o
	rm -f *~
	rm ecd2
