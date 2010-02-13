all:    readevents3 timetag_io2.o

timetag_io2.o: timetag_io2.c usbtimetagio.h
	gcc -Wall -O2 -UDEBUG -c timetag_io2.c

readevents3: readevents3.c timetag_io2.o usbtimetagio.h
	gcc -Wall -lm -O2 -o readevents3 timetag_io2.o readevents3.c

.PHONY: clean
clean:
	rm -f timetag_io2.o
	rm -f readevents3
	rm -f *~
