all:   chopper chopper2 pfind decompress costream splicer diagnosis transferd  getrate diagbb84

chopper: chopper.c
	gcc -Wall -O3 -o chopper chopper.c -lm

chopper2: chopper2.c
	gcc -Wall -O3 -o chopper2 chopper2.c

pfind: pfind.c
	gcc -Wall -O3 -o pfind pfind.c -lfftw3 -lm

decompress: decompress.c
	gcc -Wall -O3 -o decompress decompress.c

costream: costream.c
	gcc -Wall -O3 -o costream costream.c -lm

splicer: splicer.c
	gcc -Wall -O3 -o splicer splicer.c

diagnosis: diagnosis.c
	gcc -Wall -O3 -o diagnosis diagnosis.c

diagbb84: diagbb84.c
	gcc -Wall -O3 -o diagbb84 diagbb84.c

transferd: transferd.c
	gcc -Wall -O3 -o transferd transferd.c

getrate: getrate.c
	gcc -Wall -O3 -o  getrate getrate.c

clean:
	rm -f chopper
	rm -f chopper2
	rm -f pfind
	rm -f decompress
	rm -f costream
	rm -f splicer
	rm -f diagnosis
	rm -f diagbb84
	rm -f transferd
	rm -f getrate
	rm -f getrate2
