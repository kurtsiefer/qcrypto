/* rnd.c:   Part of the quantum key distribution software. These are the
            functions for pseudorandom number generation and parity
	    generation.

	    Description & reasoning see main error correction file
	    Version as of 20070101

 Copyright (C) 2005-2006 Christian Kurtsiefer, National University
                         of Singapore <christian.kurtsiefer@gmail.com>

 This source code is free software; you can redistribute it and/or
 modify it under the terms of the GNU Public License as published 
 by the Free Software Foundation; either version 2 of the License,
 or (at your option) any later version.

 This source code is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 Please refer to the GNU Public License for more details.

 You should have received a copy of the GNU Public License along with
 this source code; if not, write to:
 Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

--

   parity function. Should do something like a __builtin_parity, but runs on a
   gcc 3.3  atgument is a 32 bit unsigned int, result is 1 for odd and 0 for
   even parity */

/* status: 22.3.06 12:00 chk */
#include "rnd.h"

int __RNG_calls = 0; /* for test purposes */


/* takes less than 17 nsec on my laptop */
int parity(unsigned int a) {
    int b;
    int c,d0;
    asm  ("movl $0,%2\n"
	  "\tmovl %3,%0\n"
	  "\tmovl %0,%1\n"
	  "\tshrl $16,%1\n"
	  "\txorl %0,%1\n"
	  "\tmovl %1,%0\n"
	  "\tshrl $8,%1\n"
	  "\txorl %1,%0\n"
	  "\tjpe 1f\n"
	  "\tmovl $1,%2\n"
	  "1:"
	  : "=&a" (d0), "=&D" (c), "=&c" (b)
	  : "d" (a)
	);
    return b;
} 

/* this is an implementation of an m-sequence */

/* PSRNG fuction which sets a seed */
unsigned int __PRNG_state;
void set_PRNG_seed(unsigned int seed) {
    __PRNG_state=seed;
}
/* get k bits from PSRNG */
unsigned int PRNG_value(int k) {
    int k0;
    int b;
    for (k0=k;k0;k0--) {
	b=parity(__PRNG_state & PRNG_FEEDBACK);
	__PRNG_state <<= 1; __PRNG_state += b;
    }
    return ((1<<k)-1) & __PRNG_state;
}

/* version which iterates the PRNG from a given state location */
unsigned int PRNG_value2(int k, unsigned int *state) {
    int k0;
    int b;
    for (k0=k;k0;k0--) {
	b=parity( *state & PRNG_FEEDBACK);
	*state <<= 1; *state += b;
    }
    __RNG_calls++;
    return ((1<<k)-1) & *state;
}
unsigned int PRNG_value2_32(unsigned int *state) {
    int k0;
    int b;
    for (k0=32;k0;k0--) {
	b=parity( *state & PRNG_FEEDBACK);
	*state <<= 1; *state += b;
    }
    __RNG_calls++;
    return *state;
}


int RNG_calls(void) {return __RNG_calls;};
