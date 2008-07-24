/* errcorrect.h: Part of the quantum key distribution software. This 
                 file contains message header definitions for the error
		 correction procedure. See main file (ecd2.c) for usag
		 details. Version as of 20071201
	    
 Copyright (C) 2005-2007 Christian Kurtsiefer, National University
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

   header file containing the definitions of the message headers for the error
   correction procedure. A more detailled description of the headers can be
   found in the file errc_formats.

   first version chk 22.10.05
   status 22.3.06 12:00chk
   fixed message 8 for bell value transmission

*/

/* this one is just a mockup for reading a message to determine its length.
   It represents only the common entry at the begnning of all message files */
typedef struct ERRC_PROTO {
    unsigned int tag; /* always 6 */
    unsigned int bytelength; /* including header */
} errc_p__;
#define ERRC_PROTO_tag 6

/* packet for PRNG based subset for bit subset transmission in err estim */
typedef struct  ERRC_ERRDET_0 {
    unsigned int tag;               /* always 6 */
    unsigned int bytelength;        
    unsigned int subtype;           /* 0 for PRNG based subset */
    unsigned int epoch;             /* defines epoch of first packet */
    unsigned int number_of_epochs;  /* defines implicitly the block length */
    unsigned int seed;              /* seed for PRNG */
    unsigned int numberofbits;      /* bits to follow */
    unsigned int errormode;         /* initial error est skip? */
    float BellValue;                /* may contain a value for Bell violat */
} errc_ed_0__;
#define ERRC_ERRDET_0_subtype 0

/* packet for explicitely indexed bit fields with a good RNG for err est */
typedef  struct ERRC_ERRDET_1 {
    unsigned int tag;               /* always 6 */
    unsigned int bytelength;
    unsigned int subtype;           /* 1 for good random number based subset */
    unsigned int epoch;             /* defines epoch of first packet */
    unsigned int number_of_epochs;  /* defines implicitly the block length */
    unsigned int bitlength;         /* compression bit width for index diff */
    unsigned int numberofbits;      /* number of bits to follow */
    unsigned int errormode;         /* initial error est skip? */
} errc_ed_1__;

/* packet for requesting more sample bits */
typedef struct ERRC_ERRDET_2 {
    unsigned int tag;               /* 6 for an error correction packet */
    unsigned int bytelength;        /* length of the packet; fixed to 24 */
    unsigned int subtype;           /* 2 for request of bit number packet */
    unsigned int epoch;             /* defines epoch of first packet */
    unsigned int number_of_epochs;  /* length of the block */
    unsigned int requestedbits;     /* number of additionally required bits */
} errc_ed_2__;

#define ERRC_ERRDET_2_subtype 2

/* Acknowledgment packet for communicating the error rate */
typedef struct ERRC_ERRDET_3 {
    unsigned int tag;               /* 6 for an error correction packet */
    unsigned int bytelength;        /* the length of the packet incl header */
    unsigned int subtype;           /* 3 for request of bit number packet */
    unsigned int epoch;             /* defines epoch of first packet */
    unsigned int number_of_epochs;  /* length of the block */
    unsigned int tested_bits;       /* number of bits tested */
    unsigned int number_of_errors;  /* number of mismatches found */
} errc_ed_3__;
#define ERRC_ERRDET_3_subtype 3

/* first parity check bit info */
typedef struct ERRC_ERRDET_4 {
    unsigned int tag;               /* 6 for an error correction packet */
    unsigned int bytelength;        /* the length of the packet incl header */
    unsigned int subtype;           /* 4 for request of bit number packet */
    unsigned int epoch;             /* defines epoch of first packet */
    unsigned int number_of_epochs;  /* length of the block */
    unsigned int k0;                /* size of partition 0 */
    unsigned int k1;                /* size of partition 1 */
    unsigned int totalbits;         /* number of bits considered */
    unsigned int seed;              /* seed for PRNG doing permutation */
} errc_ed_4__;	
#define ERRC_ERRDET_4_subtype 4

/* Binary search message packet */
typedef struct ERRC_ERRDET_5 {
    unsigned int tag;               /* 6 for an error correction packet */
    unsigned int bytelength;        /* the length of the packet incl header */
    unsigned int subtype;           /* 5 for request of bit number packet */
    unsigned int epoch;             /* defines epoch of first packet */
    unsigned int number_of_epochs;  /* length of the block */
    unsigned int number_entries;    /* number of blocks with parity mismatch */
    unsigned int index_present;     /* format /presence of index data  */
    unsigned int runlevel;          /*  pass and bisectioning depth */
} errc_ed_5__;	
#define ERRC_ERRDET_5_subtype 5

#define RUNLEVEL_FIRSTPASS 0 /* for message 5 */
#define RUNLEVEL_SECONDPASS 0x80000000 /* for message 5 */
#define RUNLEVEL_LEVELMASK 0x80000000 /* for message 5 */
#define RUNLEVEL_ROUNDMASK 0x3fffffff /* for message 5 */
#define RUNLEVEL_BICONF 0x40000000 /* for message 5:
				      this indicates a biconf search */


/* BIOCNF initiating message */
typedef struct ERRC_ERRDET_6 {
    unsigned int tag;               /* 6 for an error correction packet */
    unsigned int bytelength;        /* the length of the packet (28) */
    unsigned int subtype;           /* 6 for request of bit number packet */
    unsigned int epoch;             /* defines epoch of first packet */
    unsigned int number_of_epochs;  /* length of the block */
    unsigned int seed;
    unsigned int number_of_bits;    /* the number bits requested for biconf */
} errc_ed_6__;	
#define ERRC_ERRDET_6_subtype 6

/* BIOCNF response message */
typedef struct ERRC_ERRDET_7 {
    unsigned int tag;               /* 6 for an error correction packet */
    unsigned int bytelength;        /* the length of the packet (24) */
    unsigned int subtype;           /* 7 for request of bit number packet */
    unsigned int epoch;             /* defines epoch of first packet */
    unsigned int number_of_epochs;  /* length of the block */
    unsigned int parity;            /* result of the parity test (0 or 1) */
} errc_ed_7__;	
#define ERRC_ERRDET_7_subtype 7

/* privacy amplification start message */
typedef struct ERRC_ERRDET_8 {
    unsigned int tag;               /* 6 for an error correction packet */
    unsigned int bytelength;        /* the length of the packet (32) */
    unsigned int subtype;           /* 8 for request of bit number packet */
    unsigned int epoch;             /* defines epoch of first packet */
    unsigned int number_of_epochs;  /* length of the block */
    unsigned int seed;              /* new seed for PRNG */
    unsigned int lostbits ;         /* number of lost bits in this run */
    unsigned int correctedbits;     /* number of bits corrected in */
} errc_ed_8__;	
#define ERRC_ERRDET_8_subtype 8




