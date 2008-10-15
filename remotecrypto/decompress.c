/* decompress.c : Part of the quantum key distribution software (auxiliary)
                  for decompressing t2 files.
                  Description see below. Version as of 20070101

 Copyright (C) 2005 Christian Kurtsiefer, National University
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
 program to test the decompressor for t2 files.

usage: decompress filename

outputs the time data (not epoch-corrected) in hex to stdout

remarks:
  - token bitmask is missing

*/

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define RAW1_SIZE 3200000 /* should last for 700 kcps */ 
typedef struct header_2 { /* header for type-2 stream packet */
    int tag;  
    unsigned int epoc;
    unsigned int length;
    int timeorder;
    int basebits;
    int protocol;
} h2;

#define TYPE_1_TAG 1
#define TYPE_1_TAG_U 0x101
#define TYPE_2_TAG 2
#define TYPE_2_TAG_U 0x102
#define TYPE_3_TAG 3
#define TYPE_3_TAG_U 0x103
#define TYPE_4_TAG 4
#define TYPE_4_TAG_U 0x104

/* function to fill buffer with stream-2 raw data. eats an input buffer, a
   file handle, a max size in bytes, and a pointer to a header_2 structure.
   returns an error code. */
int get_stream_2(void *buffer, int handle, int maxsize, 
		 struct header_2 *head, int* realsize) {
    int retval;
    int bitnum;
    struct header_2* h;
   
    retval=read(handle,buffer,maxsize);
    if (!retval) return 16; /* nothing available */
    if (!(retval+1)) return 17; /* other error */
    if (retval<sizeof(struct header_2)) return 18; /* incomplete read */
    h=(struct header_2 *)buffer; /* at beginning of stream */
    /* consistency check on length and tag */
    if ((h->tag!=TYPE_2_TAG) && (h->tag!=TYPE_2_TAG_U)) return 28;
    if (h->length) {
	bitnum=((retval-sizeof(struct header_2))*8-h->basebits-
		h->timeorder-31)/h->length - h->basebits-h->timeorder;
	if ((bitnum<0) | (bitnum >32)) return 19;
    }
    *realsize = retval; /* read in bytes */
    *head=h[0];
    return 0;
}

int main(int argc, char *argv[]) {
    char fname[200]; /* infile name */
    char *buffer;
    int handle;
    int retval;
    struct header_2 head2;
    int realsize2;
    unsigned int *pointer2;
    unsigned long long intime;
    int i,j,k,resbits,bitstoread2,emergency_break;
    unsigned int tdiff,readword,tdiff_bitmask,patternmask,opatt;
    int pattern;
    int type2bitwidth,type2datawidth; /* for decompression */

    sscanf(argv[1],"%s",fname);
    buffer=(char *)malloc(RAW1_SIZE); /* double usage */

    handle=open(fname,O_RDONLY);

    retval=get_stream_2(buffer,handle,RAW1_SIZE,&head2,&realsize2);
    printf("retval from getstream: %d, realsize:%d\n",retval,realsize2);

    printf("entries: %d, bitwidth: %d\n",head2.length, head2.timeorder);

    i=0; /* standard epoch */

    /* running decompressor */
	pointer2=(unsigned int *)(buffer+sizeof(struct header_2));
	printf("original buffer: %p,pointer2: %p\n",buffer,pointer2);
        /* adjust to current epoch origin */
	intime=0; 
        /* for (j=0;j<30;j++) printf("b[%d ]= %02x; ",j,buffer[j]); */
	/* prepare decompression */
	j=0;readword = pointer2[j++]; /* raw buffer */
	/* printf("read1: %04x, start:%x j:%d\n",readword,pointer2[0],j); */
	resbits=32; /* how much to eat */
	type2bitwidth=head2.timeorder; type2datawidth=head2.basebits;
	bitstoread2=type2bitwidth+type2datawidth; /* has to be <32 !! */
	tdiff_bitmask = ((1<<type2bitwidth)-1); /* for unpacking */
	patternmask= (1<<type2datawidth)-1;
	/* printf("tdiff_bitmask: %x\n",tdiff_bitmask); */
	emergency_break=
	    (realsize2-sizeof(struct header_2))/sizeof(unsigned int);
	k=0;/* count local events */
	do { /* go through buffer */
	    if (resbits>=bitstoread2) {
		/* printf("*1"); */
		tdiff=(readword>>(resbits-bitstoread2));
		resbits-=bitstoread2;
		if (!resbits) {
		    /* printf("*2"); */
		    readword=pointer2[j++];resbits=32;
		}
	    } else {
		/* printf("*3"); */
		resbits=bitstoread2-resbits;
		tdiff=(readword<<resbits);
		resbits=32-resbits;
		readword=pointer2[j++];
		tdiff=(tdiff | (readword>>resbits));
	    }
	    pattern= (tdiff & patternmask);
	    tdiff>>=type2datawidth;
	    
	    /* we have a time difference word now in tdiff */
	    if (tdiff &= tdiff_bitmask) { /* check for exception */  
		/* test for end of stream */
		if (tdiff==1) break; /* exit digest routine for this stream */
	    } else {/* read in complete difference */
		tdiff = readword<<(32-resbits);
		/* printf("*E(r=%d)",resbits); */
		/* printf("rw1: %x tdiff1: %x,",readword,tdiff); */
		readword=pointer2[j++];
		/* printf("rw2: %x , tdiff: %x",readword,tdiff); */
                /* catch shift 'feature' - normal */
		if (resbits & 0x1f) tdiff |= (readword>>resbits);
		/* printf("resbits: %d,rw: %x",resbits,readword); */
		/* printf("patt: %x tdiff3: %x",pattern,tdiff); */
		opatt=pattern;
		/* tdiff |=  (pattern<<32); */
		/* printf("tdiff4: %x *4",tdiff); */
		pattern=tdiff&patternmask;
		tdiff >>=type2datawidth;
		tdiff|=(opatt<<(32-type2datawidth));
	    }
	    /* we now have a valid difference */
	    intime +=tdiff;
	    printf("k=%d: diff=%x, result: %08x, pattern :%x\n",k,tdiff,(unsigned int)intime,pattern);
	    /* buf2_fast[(int)(mask & (intime>>fres))]++;
	       buf2_slow[(int)(mask & (intime>>sres))]++; */
	    k++;
	} while (j<emergency_break);
	/* printf("control point 14\n");
	   printf("head2.length: %d, j:%d, eme: %d, k: %d,tdiff: %d\n", 
	   head2.length,j,emergency_break,k,tdiff); */
    return 0;
}

