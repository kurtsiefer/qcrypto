/* diagnosis.c : Part of the quantum key distribution software for analyzing
                 raw key files in service mode for generating a correlation
		 matrix from t3 files. Description see below
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
   this program digests a service file, and outputs a correlation matrix
   together with some service parameters 
   
   usage: diagnosis [-q] servicefile

   the program ejects various informations extracted from the service files
   and displays it in a formatted version. If the -q option is set, the program
   does not do any formatting but outputs the information in a single line.

   

*/

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#define FNAMELENGTH 200  /* length of file name buffers */
#define FNAMFORMAT "%200s"   /* for sscanf of filenames */
#define DEFAULT_OUTMODE 0 /* supply formatted output */

#define RAW3i_SIZE 1500000  /* more than enough? */


typedef struct header_3 {/* header for type-3 stream packet */
    int tag;
    unsigned int epoc;
    unsigned int length;
    int bitsperentry; 
} h3;

#define TYPE_1_TAG 1
#define TYPE_1_TAG_U 0x101
#define TYPE_2_TAG 2
#define TYPE_2_TAG_U 0x102
#define TYPE_3_TAG 3
#define TYPE_3_TAG_U 0x103
#define TYPE_4_TAG 4
#define TYPE_4_TAG_U 0x104

char *errormessage[] = {
  "No error.",
  "Error reading file/directory name for type-3 input packets.", /* 1 */
  "cannot malloc input buffer.",
  "canot open input file",
  "input file too large",
  "error reading file (nothing there)", /* 5 */
  "wrong file type (type 3 expected)" ,
  "stream 3 size inconsietency",
  "not 8 bits per entry",

};
int emsg(int code) {
  fprintf(stderr,"%s\n",errormessage[code]);
  return code;
};

int decode[16]={-1,0,1,-1,   2,-1,-1,-1,  3,-1,-1,-1,  -1,-1,-1,-1};

int main (int argc, char *argv[]) {
    char fname[FNAMELENGTH]={""}; /* stream files */
    char *buffer3i, *inpointer;
    int handle, retval;
    struct header_3 *h;
    int bytenum;
    unsigned int ui;
    int histo[16]; /* for keeping tyhe histogram */
    int garbage1, garbage2, total, okcount,a,b;
    char detlabel[5]="V-H+";
    int opt;
    int outmode = DEFAULT_OUTMODE; /* 0: formatted, 1: unformatted */

    /* parsing option */
    opterr=0;
    while ((opt=getopt(argc, argv, "q"))!= EOF) {
	switch (opt) {
	    case 'q': /* set quiet option */
		outmode = 1;
		break;
	}
    }

    /* get buffer*/
    if (!(buffer3i=(char*)malloc(RAW3i_SIZE))) return -emsg(2);

    /* get filename*/
    if (1!=sscanf(argv[optind],FNAMFORMAT,fname)) return -emsg(1);
    
    /* get file */
    handle=open(fname,O_RDONLY);
    if (-1==handle) return -emsg(3);

    retval=read(handle,buffer3i,RAW3i_SIZE);
    if (retval==RAW3i_SIZE) return -emsg(4);
    if (!retval) return 5; 

    /* consistency check at end */
    h=(struct header_3 *)buffer3i;

    /* printf("length: %d\n",h->length); */

    if ((h->tag!=TYPE_3_TAG) && (h->tag!=TYPE_3_TAG_U)) return 6;
    bytenum= (h->length*h->bitsperentry+7)/8+sizeof(struct header_3);
    bytenum = (bytenum>>2) + ((bytenum &3)?1:0); /* words */
    if (bytenum*4!=retval) return 7;
    /* protocol bit match? */
    if (h->bitsperentry != 8) return 8;

    /* close file */
    close(handle);

    /* prepare histogram */
    inpointer=(char *)(buffer3i+sizeof(struct header_3));
    for (ui=0;ui<16;ui++) histo[ui]=0;
    
    /* fill histo */
    garbage1=0;garbage2=0;okcount=0;total=h->length;
    for (ui=0;ui<h->length;ui++) {
	b=decode[inpointer[ui]&0xf]; /* bob */
	a=decode[(inpointer[ui]>>4)&0xf]; /* alice */
	if (a<0) garbage1++;
	if (b<0) garbage2++;
	if ((a>=0) && (b>=0)) {
	    histo[a*4+b]++;
	    okcount++;
	}
    }
    
    switch (outmode) {
	case 0: /* formatted output */
	    /* print  histogram */
	    printf("det2:       V       -       H       +  \n");
	    printf("-------------------------------------\n");
	    
	    for (a=0;a<4;a++) {
		printf("det1= %c | %5d   %5d   %5d   %5d\n",
		       detlabel[a],histo[4*a],histo[4*a+1],histo[4*a+2],
		       histo[4*a+3]);
	    }
	    /* print data */
	    printf("ok: %d, total: %d, garbage1: %d, garbage2: %d\n",
		   okcount,total, garbage1,garbage2);
	    break;
	case 1: /* only one line */
	    for (a=0;a<16;a++) printf("%d ",histo[a]); /* det histogram */
	    printf("%d %d %d %d\n",okcount,total, garbage1,garbage2);
	    break;
    }
    return 0;
}
