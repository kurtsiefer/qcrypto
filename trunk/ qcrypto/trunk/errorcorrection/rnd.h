/* rnd.h:   Part of the quantum key distribution software. This is the
            header files for the random number sources
	    status of this document: 22.3.06chk

	    Description see main error correction file and rnd.c for the
	    proper pseudorandom number generation functions.
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

*/

#define PRNG_FEEDBACK 0xe0000200

int RNG_calls(void);

int parity(unsigned int a0);

void set_PRNG_seed(unsigned int );

unsigned int PRNG_value(int);

unsigned int PRNG_value2(int, unsigned int *);
unsigned int PRNG_value2_32(unsigned int *);
