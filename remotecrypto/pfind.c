/* pfind.c :   Part of the quantum key distribution software for finding the
               time difference between two timestamped correlated detctor
	       data streams. Description see below. Version as of 20070101

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

   Program on side B to find a coincidence time difference. Takes a directory
   or file with type-2 and type-1 files, and concatenates a given number of
   packets starting with a given epoch number, evaluates the time difference
   in multiples of 1/8 nsec, and returns that to stdout or any other file,
   eventually with some reliability information on the found timing difference.


   usage:  pfind [-i type-2 streamfile] | [-d type-2 directory] | [-s socket2]
                 [-I type-1 streamfile] | [-D type-1 directory] | [-S socket1]
		 -e startepoch  
		 [-n epochnums] 
		 [-l logfilename] [-v verbosity]
		 [-k] [-K]
		 [-r resolution]
		 [-q bufferwidth ]

 DATA STREAM OPTIONS:
   -i infile2:      filename of type-2 packets. Can be a file or a socket
                    and has to supply binary data according to the type-2
		    data spec from the chopper program.
   -d dir2:         All type-2 packets are saved into the directory dir2, with
                    the file name being the epoch (filling zero expanded)
		    in hex. Filename is not padded at end.
   -I infile1:      filename of type-1 packets. Can be a file or a socket
                    and has to supply binary data according to the type-1
		    data spec from the chopper2 program.
   -D dir1:         All type-1 packets are saved into the directory dir1, with
                    the file name being the epoch (filling zero expanded)
		    in hex. Filename is not padded at end.
   -k :             if set, type-2 streams are removed aafter consumption
		    if the directory input has been chosen.
   -K :             if set, type-1 streams are removed aafter consumption
		    if the directory input has been chosen.

 DATA MANAGEMENT OPTIONS:
   -e startepoch    epoch to start with. default is 0.
   -n epochnums     define a runtime of epochums epochs before looking for a
                    time delay. default is 1.

 RESOLUTION:
   -r resolution   resolution of timing info in nanoseconds. Will be rounded
                   to closest power of 1 nsec. Default is 2 nsec.
   -q bufferwidth  order of FFT buffer size. Defines the wraparound size
                   of the coarse / fine periode finding part. defaults
		   to 17 (128k entries), must lie within 12 and 23.

 LOGGING & NOTIFICATION:
   -l logfile:   The resulting time difference or details are logged into this
                 file. if this option is not specified, STDOUT is used.
		 The verbosity level controls the granularity of details.
   -V level:     Verbosity level control. level is integer, and by default set
                 to 0. The logging verbosity criteria are:
		 level<0 : no output
		 0 : output difference (in plaintext decimal ascii)
		 1 : output difference and reliability info w/o text
		 2 : output difference and reliability info with text
		 3 : more text 

  History:
  written specs: 21.8.05 chk
  added -q option for buffer order parameter 4.3.06chk


  ToDo:
  confirm tags of files in opening procedures -ok
  are headers filled correctly in get_stream_x? -ok??
  EPOCH OFFSet calculation in stream processing correct? -ok?
  change type2 endword to 0-00000 in filespec and decompressor 
  check resolution initiaization -ok?
  typedef should go in one header file
  killmode also for single files? 
  test killmode works, and new stream 2 file closing works

*/

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <fftw3.h>
#include <time.h>
#include <sys/time.h>

/* default definitions */
#define DEFAULT_VERBOSITY 0
#define FNAMELENGTH 200  /* length of file name buffers */
#define FNAMFORMAT "%200s"   /* for sscanf of filenames */
#define DEFAULT_UEPOCH 0   /* choose no universal epoch option */
#define DEFAULT_KILLMODE1 0 /* don't delete stream-1 files */
#define DEFAULT_KILLMODE2 0 /* don't delete stream-2 files */
#define DEFAULT_STARTEPOCH 0
#define DEFAULT_EPOCHNUMBER 1 /* How many epochs to consider */
#define DEFAULT_RESOLUTION 2 /* resolution in nanoseconds */
#define RAW1_SIZE 6400000 /* should last for 1400 kcps */ 
#define RAW2_SIZE RAW1_SIZE  /* for this: buffer1=buffer2 */
/* definitions for folding */
#define DEFAULT_BBW 17 /* default buffer_bitwidth */
#define BBW_MIN 12 /* limits for bufer width */
#define BBW_MAX 23 /* limits for buffer width */
#define CRES_ORDER (11+3) /* coarse resolution is 2048 nsec */
#define COARSE_RES (1<<CRES_ORDER)

/* structures for input buffer headers */
typedef struct header_1 { /* header for type-1 stream */
    int tag;
    unsigned int epoc;
    unsigned int length;
    int bitsperentry;
    int basebits;
} h1;

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


typedef struct rawevent {unsigned int cv; /* most significan word */
    unsigned int dv; /* least sig word */} re;

/* error handling */
char *errormessage[31] = {
  "No error.",
  "Error reading in verbosity argument.", /* 1 */
  "Error reading file/directory name for type-2 packets.",
  "duplicate definition of type-2 file.",
  "Error reading file/directory name for type-3 packets.",
  "duplicate definition of type-3 file.", /* 5 */
  "error parsing startepoch.",
  "error parsing epoch number.",
  "Error parsing resolution",
  "Resolution (in nsec) is not power of 2",
  "Error parsing logfile name.", /* 10 */
  "Cannot malloc raw buffer",
  "No content reading stream 1.",
  "General I/O error reading stream 1.",
  "incomplete read on stream 1.",
  "stream 1 inconsistency detected.",  /* 15 */
  "No content reading stream 2.",
  "General I/O error reading stream 2.",
  "incomplete read on stream 2.",
  "stream 2 inconsistency detected.",
  "error opening stream 1 source", /* 20 */
  "epoch mismatch in stream 1.",
  "error removing stream 1 file.",
  "error opening stream 2 source",
  "epoch mismatch in stream 2.",
  "error removing stream 2 file.", /* 25 */
  "error opening logfile.",
  "wrong stream type detected when looking for stream-1.",
  "wrong stream type detected when looking for stream-2.",
  "cannot parse buffer bit width",
  "FFT size order out of range (must be 12..23)", /* 30 */
};

int emsg(int code) {
  fprintf(stderr,"%s\n",errormessage[code]);
  return code;
};

/* global variables for IO handling */
int verbosity_level = DEFAULT_VERBOSITY;
char fname1[FNAMELENGTH]="";
char fname2[FNAMELENGTH]="";
char logfname[FNAMELENGTH]="";
char ffnam[FNAMELENGTH+10];
int type1mode = 0; /* no mode defined. other tpyes:
		      1: single file, 2: directory save, ... */
int type2mode = 0; /* same as for type-1 files */
int killmode1 = DEFAULT_KILLMODE1 ; /* if != 1, infile is deleted after use */
int killmode2 = DEFAULT_KILLMODE2 ; /* if != 1, infile is deleted after use */
int handle1, handle2; /* global handles for input files */


/* buffer for summation register */
int *buf1_fast, *buf1_slow, *buf2_fast, *buf2_slow;

/* buffer for fourier transforms */
fftw_complex *f1, *f2 ;/* transform fields */
fftw_plan plan1, plan2, plan3; /* ftrafo plans */ 


/* function to fill buffer with stream-1 raw data. eats an input bufferpointer,
   a file handle, a max size in bytes, and a pointer to a header_1 struct.
   returns an error code.  */ 
int get_stream_1(void *buffer, int handle, int maxsize,
		 struct header_1 *head) {
    int retval;
    int eidx;
    unsigned int *ib = buffer;
    struct header_1 *h; /* for local storage */
    retval=read(handle,buffer,maxsize);
    if (!retval) return 12; /* nothing available */
    if (!(retval+1)) return 13; /* other error */
    if (retval<(int)sizeof(struct header_1)) return 14; /* incomplete read */
    h=(struct header_1 *)buffer; /* at beginning of stream */
    /* consistency check at end */
    if ((h->tag!=TYPE_1_TAG) && (h->tag!=TYPE_1_TAG_U)) return 27;
    if (h->length) {
	eidx=(h->length*sizeof(struct rawevent)+sizeof(struct header_1))
	    /sizeof(unsigned int);
	if (eidx!=(retval/(int)sizeof(unsigned int)-2))
	    return 15; /* length mismatch */
	if (ib[eidx] | ib[eidx+1]) return 15; /* last word nonzero */

    } else {
	if (retval-sizeof(struct header_1) % sizeof(struct rawevent))
	    return 15; /* size mismatch */
	eidx=retval/sizeof(unsigned int);
	if (ib[eidx-1] |ib[eidx-2]) return 15; /* last word nonzero */
	if (!(ib[eidx-3] |ib[eidx-4])) return 15; /* last real entry zero */ 
	h->length=
	    (retval-sizeof(struct header_1))/sizeof(struct rawevent)-1;
    }
    *head=h[0]; /* return pointer to header */
    return 0;
}
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
    if (retval<(int)sizeof(struct header_2)) return 18; /* incomplete read */
    h=(struct header_2 *)buffer; /* at beginning of stream */
    /* consistency check on length and tag */
    if ((h->tag!=TYPE_2_TAG) && (h->tag!=TYPE_2_TAG_U)) return 28;
    if (h->length) {
	bitnum=(retval-sizeof(struct header_2))*8/(h->length+1)
	    - h->basebits-h->timeorder;
	if ((bitnum<0) | (bitnum >32)) {
	    fprintf(stderr,"bitnum :%d, stream %08x, ",bitnum,h->epoc);
	    return 19;}
    }
    *realsize = retval; /* read in bytes */
    *head=h[0];
    return 0;
}
/* helper for name. adds a slash, hex file name and a termial 0 */
char hexdigits[]="0123456789abcdef";
void atohex(char* target,unsigned int v) {
    int i;
    target[0]='/';
    for (i=1;i<9;i++) target[i]=hexdigits[(v>>(32-i*4)) & 15];
    target[9]=0;
}


/* buffer for fourier transforms */
fftw_complex *f1, *f2 ;/* transform fields */
fftw_plan plan1, plan2, plan3; /* ftrafo plans */ 

/* fill complex field with int filed, do transform and retrun max/sigma */
void findmax(int *buf1, int *buf2, double* maxval, double *sigma, 
	     double* mean,int *pos,int size,int ecnt1, int ecnt2) {
    int i; /* counter index */
    double ai,ar,br,bi; /* temporary variables */
    double sx,sxx;
    int maxpos;

    /* clear double buffers / transfer int to double buffers */
    ar=((double)ecnt1)/size; /* to get mean at zero */
    br=((double)ecnt2)/size;
    for (i=0;i<size;i++){
	f1[i][0]=(double)buf1[i]-ar;f1[i][1]=0.;
	f2[i][0]=(double)buf2[i]-br;f2[i][1]=0.;
    }
    /* do forward transformations */
    fftw_execute(plan1);  fftw_execute(plan2); 
    /* do conjugate and multiplication into array 1 */
    for (i=0;i<size;i++){
	ar=f1[i][0];ai=f1[i][1]; br=f2[i][0];bi=f2[i][1];
	f1[i][0]=ar*br+ai*bi;f1[i][1]=ar*bi-ai*br;
    }
    /* do do backtransform */
    fftw_execute(plan3);
    /* evaluate max, stddev and mean */
    *maxval=0.;maxpos=0;sxx=0;sx=0.;
    for (i=0;i<size;i++){
	ar=f1[i][0];if (ar > *maxval) {maxpos=i; *maxval=ar;}
	sx+=ar;sxx+=(ar*ar);
    }
    /* return values properly back */
    *mean = sx / size;
    *sigma = sqrt(sxx/size- (*mean) * (*mean));
    *pos=maxpos;
}

/* lookup table for correction */
#define PL1 0x10000  /* +1 step fudge correction for epoc index mismatch */
#define MI1 0xffff0000 /* -1 step fudge correction */
unsigned int overlay_correction[16]= {0,PL1,0,MI1, MI1,0,PL1,0,
				      0,MI1,0,PL1, PL1,0,MI1,0};


int main (int argc, char *argv[]) {
    FILE* loghandle; /* for log files */
    unsigned int startepoch = DEFAULT_STARTEPOCH; /* epoch to start with */
    int epochnumber = DEFAULT_EPOCHNUMBER; /* # of epochs to read  */
    int resolution = DEFAULT_RESOLUTION;  /* in units of nsec */
    int resorder; /* shift mask for resolution */
    int i,j,opt,retval; /* various working variables */
    unsigned int ju,ku; /* whereever it is needed */
    char *buffer1, *buffer2;  /* buffers for packed files */
    struct header_1 head1; /* for input stream 1 */
    struct header_2 head2; /* for input stream 2 */
    unsigned long long mask, intime;
    int fres,sres;  /* shift information for coarse / fine periode finder */
    int ecnt1,ecnt2; /* counting events in source files */
    unsigned long long epoch_offset; /* for epoch correction */
    int resbits,realsize2,bitstoread2,pattern;
    unsigned int tdiff,tdiff_bitmask,readword,patternmask;
    int emergency_break; /* contains maximum index for strean-2 decompress */
    long long int t0,timediff; /* final timedifference in 1/8 nsec */
    double maxval_s, maxval_f, sigma_s, sigma_f, mean_s, mean_f; /* results */
    int pos_s, pos_f; /* position of maximum */
    int type2bitwidth,type2datawidth; /* for decompression */
    struct rawevent *pointer1; /* for parsing stream-1 */
    unsigned int *pointer2; /* for parsing stream 2 */
    unsigned int thisepoch; /* for epoch calculation */
    int overlay;
    long long int se_in; /* for entering startepoch both in hex and decimal */
    int buf_bitwidth = DEFAULT_BBW; /* length of individual buffers */
    int zhs = (1<<DEFAULT_BBW);

    /* parsing options */
    opterr=0; /* be quiet when there are no options */
    while ((opt=getopt(argc, argv, "i:d:I:D:kKe:n:r:l:V:q:")) != EOF) {
	switch (opt) {
	    case 'V': /* set verbosity level */
		if (1!=sscanf(optarg,"%d",&verbosity_level)) return -emsg(1);
		break;
	    case 'i': case 'd': /* stream2 name and type */
		if (1!=sscanf(optarg,FNAMFORMAT,fname2)) return -emsg(2);
		fname2[FNAMELENGTH-1]=0;  /* security termination */
		if (type2mode) return -emsg(3); /* already defined mode */
		if (opt=='i') type2mode=1; else type2mode=2;
		break;
	    case 'I': case 'D': /* stream-1 name and type */
		if (1!=sscanf(optarg,FNAMFORMAT,fname1)) return -emsg(4);
		fname1[FNAMELENGTH-1]=0;  /* security termination */
		if (type1mode) return -emsg(5); /* already defined mode */
		if (opt=='I') type1mode=1; else type1mode=2;
		break;
	    case 'k': /* kill mode stream 2 */
		killmode2=1;
		break;
	    case 'K': /* kill mode stream 1 */
		killmode1=1;
		break;
	    case 'e': /* read startepoch */
		if (1!=sscanf(optarg,"%lli",&se_in)) return -emsg(6);
		startepoch=se_in & 0xffffffff;
		break;
	    case 'n': /* read startepoch */
		if (1!=sscanf(optarg,"%d",&epochnumber)) return -emsg(7);
		break;
	    case 'r': /* resolution */
		if (1!=sscanf(optarg,"%d",&resolution)) return -emsg(8);
		i=resolution;
		for (resorder=0;i>1;i /=2) resorder++;
		if (resolution!=(1<<resorder)) return -emsg(9);
		break;
	    case 'l': /* logfile name */
		if (sscanf(optarg,FNAMFORMAT,logfname) != 1) return -emsg(10);
		logfname[FNAMELENGTH-1]=0;  /* security termination */
		break;
	    case 'q': /* get buffer order */
		if (sscanf(optarg,"%d",&buf_bitwidth) != 1) return -emsg(29);
		if (buf_bitwidth<BBW_MIN || buf_bitwidth >BBW_MAX) 
		    return -emsg(30);  /* out of range */
		break;
		
	}
    }

    /* check argument consistency */
    i=resolution;
    for (resorder=0;i>1;i /=2) resorder++;
    if (resolution!=(1<<resorder)) return -emsg(9);
    resorder +=3; /* from now on, it refers to 1/8 nsec */
    resolution *=8; /* refers also to 1/8 nsec */

    /* consolidate buffer size */
    zhs = 1<<buf_bitwidth;

    /* allocate input buffers for packed and unpacked stuff */
    buffer1=(char *)malloc(RAW1_SIZE); /* double usage */
    buffer2=buffer1;
    if (!buffer1) return -emsg(11); /* cannot get inbuffer */

    /* prepare integer buffers for folded timings */
    buf1_fast=(int*)calloc(zhs*4,sizeof(int));
    if (!buf1_fast) return -emsg(6);
    buf1_slow=&buf1_fast[zhs];buf2_fast=&buf1_slow[zhs];
    buf2_slow=&buf2_fast[zhs];

    /* prepare event isolation constants */
    mask = zhs-1;
    fres = resorder; /* shifting for fine order */
    sres = CRES_ORDER; /* shifting for coarse timng */

    /* concatenate events into buffer; first, the type-1 stream events */
    ecnt1=0;  /* event counter 1 */

    /* eventually open stream 1 */
    if (type1mode==1) { /* single file */
	if (fname1[0]) { /* not stdin */
	    if (-1==(handle1=open(fname1,O_RDONLY))) return -emsg(20);
	} else { handle1=0; } /* stdin */
    }
    for (i=0;i<epochnumber;i++) {
	thisepoch=startepoch+(unsigned int)i;
	/* evtl. open stream 1 */
	if (type1mode==2) { /* file in directory */
	    strncpy(ffnam, fname1, FNAMELENGTH);
	    atohex(&ffnam[strlen(ffnam)],thisepoch);
	    handle1=open(ffnam,O_RDONLY);
	    if(-1==handle1) { 
		fprintf(stderr,"ep:>%s<\n",ffnam);
		return -emsg(20);
	    }
	}

	/* buffer stream 1 */
	retval=get_stream_1(buffer1,handle1,RAW1_SIZE,&head1);
	if (retval) return -emsg(retval);
	/* check epoch consistency */
	if (head1.epoc!=thisepoch) return -emsg(21);

	/* process stream 1 */
        pointer1=(struct rawevent *)(buffer1+sizeof(struct header_1)); 

	/* adjust absolute epoch */
	overlay=((pointer1[0].cv>>28)&0xc) | ((thisepoch>>15) & 3);
	/* take upper 15 bit from epoch for offset */
	epoch_offset=((unsigned long long)
		      ((thisepoch+overlay_correction[overlay]) & 0xfffe0000)
	              )<<32;
	for (ju=0;ju<head1.length;ju++) {
	    intime=((unsigned long long)pointer1[ju].cv<<17)
		+(pointer1[ju].dv>>15)+epoch_offset; /* current timing */
	    buf1_fast[(int)(mask & (intime>>fres))]++;
	    buf1_slow[(int)(mask & (intime>>sres))]++;
	    ecnt1 ++;
	}
	/* evtl close steam 1 */
	if (type1mode==2) { /* file in directory */
	    close(handle1);
	    /* eventually remove file */
	    if (killmode1) {
		/* printf("control point 1\n"); */
		if (unlink(ffnam)) return -emsg(22);
	    }
	}
    }
    /* evtl close stream 1 */
    if (type1mode==1) { /* file is not a  directory */
	close(handle1);
	/* eventually remove file */
	if (killmode1 && (handle1!=0)) {
	    /* printf("control point 1a\n"); */

	    if (unlink(fname1)) return -emsg(22);
	}
    }
    
/*     printf("control point 10\n"); */
    /* process stream 2 data */
    ecnt2=0;  /* event counter 1 */
    /* eventually open stream 1 */
    if (type2mode==1) { /* single file */
	if (fname2[0]) { /* not stdin */
	    if (-1==(handle2=open(fname2,O_RDONLY))) {
		fprintf(stderr,"errno:%d, file: %s ",errno,fname2);
		return -emsg(23);}
	} else { handle2=0; } /* stdin */
    }
    for (i=0;i<epochnumber;i++) {
	thisepoch=startepoch+i;
	/* evtl. open stream 2 */
	if (type2mode==2) { /* file in directory */
	    strncpy(ffnam, fname2, FNAMELENGTH);
	    atohex(&ffnam[strlen(ffnam)],thisepoch);
	    handle2=open(ffnam,O_RDONLY);
	    if(-1==handle2) {
		fprintf(stderr,"(2)errno:%d, file: %s ",errno,ffnam);
		return -emsg(23);
	    }
	}
	/* printf("control point 11\n"); */

	/* buffer stream 2 */
	retval=get_stream_2(buffer2,handle2,RAW2_SIZE,&head2,&realsize2);
	if (retval) return -emsg(retval);
	/* printf("control point 12\n"); */

	/* check epoch consistency */
	if (head2.epoc!=thisepoch) return -emsg(24);
	
	/* printf("control point 13\n"); */

        /* process stream 2 */
	pointer2=(unsigned int *)(buffer2+sizeof(struct header_2));
        /* adjust to current epoch origin */
	intime=((unsigned long long)thisepoch)<<32; 
	/* prepare decompression */
	j=0;readword = pointer2[j++]; /* raw buffer */
	/* printf("first readw: %x\n",readword);*/
	resbits=32; /* how much to eat */
	type2bitwidth=head2.timeorder; type2datawidth=head2.basebits;
	bitstoread2=type2bitwidth+type2datawidth; /* has to be <32 !! */
	tdiff_bitmask = (1<<type2bitwidth)-1; /* for unpacking */
	patternmask = (1<<type2datawidth)-1;
	emergency_break=
	    (realsize2-sizeof(struct header_2))/sizeof(unsigned int);
	ku=0;/* count local events */
	do { /* go through buffer */
	    if (resbits>=bitstoread2) {
		tdiff=(readword>>(resbits-bitstoread2));
		resbits-=bitstoread2;
		if (!resbits) {readword=pointer2[j++];resbits=32;}
	    } else {
		resbits=bitstoread2-resbits;
		tdiff=readword<<resbits;
		readword=pointer2[j++];
		resbits=32-resbits;
		tdiff=(tdiff | (readword>>resbits));
	    }
	    pattern= (tdiff & patternmask);
	    tdiff>>=type2datawidth;
	    /* printf("token: %x, pattern: %x; ",tdiff& tdiff_bitmask,pattern); */
	    /* we have a time difference word now in tdiff */
	    if (tdiff &= tdiff_bitmask) { /* check for exception */
		/* test for end of stream */
		if (tdiff==1) break; /* exit digest routine for this stream */
	    } else {
		/* read in complete difference */
		tdiff=readword<<(32-resbits);
		readword=pointer2[j++];
		/* printf("e: rw=%x ",readword); */
                /* catch shift 'feature' - normal */
		if (resbits & 0x1f) tdiff |= readword>>resbits;
		tdiff >>=type2datawidth;
		tdiff |=  (pattern<<(32-type2datawidth));
	    }
	    /* we now have a valid difference */
	    intime +=tdiff;
	    /*  printf("k: %d, tdiff: %x, intime: %llx\n",k,tdiff,intime); */
	    buf2_fast[(int)(mask & (intime>>fres))]++;
	    buf2_slow[(int)(mask & (intime>>sres))]++;
	    ku++;
	} while (j<emergency_break);
/* 	printf("control point 14\n");
	printf("head2.length: %d, j:%d, eme: %d, k: %d,tdiff: %d\n",
	head2.length,j,emergency_break,k,tdiff); */
	/* consistency check */
	if (head2.length || (j>=emergency_break)) if (ku!=head2.length) {
	    fprintf(stderr,"ku: %d, announced len: %d ",ku,head2.length);
	    return  -emsg(19);
	}
	ecnt2 += ku;
	/* close evtl stream 2 */ 
	if (type2mode==2) { /* file is in a directory */
	    close(handle2);
	    /* eventually remove file */
	    if (killmode2 && (handle2!=0)) {
		if (unlink(ffnam)) return -emsg(25);
	    }
	}
	
	
    }

    /* close evtl stream 2 */ 
    if (type2mode==1) { /* file is not a  directory */
	close(handle2);
	/* eventually remove file */
	if (killmode2 && (handle2!=0)) {
	    if (unlink(fname2)) return -emsg(25);
	}
    }

    /* printf("ecnt1: %d, ecnt2: %d\n",ecnt1, ecnt2); */

    /* do the fourier thing */
    
    /* prepare fourier transform */
    f1 = fftw_malloc(sizeof(fftw_complex) * zhs);
    f2 = fftw_malloc(sizeof(fftw_complex) * zhs);
    
    plan1 = fftw_plan_dft_1d(zhs, f1, f1, FFTW_FORWARD, FFTW_ESTIMATE);
    plan2 = fftw_plan_dft_1d(zhs, f2, f2, FFTW_FORWARD, FFTW_ESTIMATE);
    plan3 = fftw_plan_dft_1d(zhs, f1, f1, FFTW_BACKWARD, FFTW_ESTIMATE);
   
    /* do job for slow array */
    findmax(buf1_slow, buf2_slow, &maxval_s, &sigma_s, &mean_s,&pos_s,
	    zhs,ecnt1,ecnt2);
    /* do job for fast array */
    findmax(buf1_fast, buf2_fast, &maxval_f, &sigma_f, &mean_f,&pos_f,
	    zhs,ecnt1,ecnt2);

    /* consolidate time difference from fast/slow values */
    if (pos_s & (zhs>>1)) pos_s |= (-zhs); /* do sign extend */
    t0=pos_s*COARSE_RES; /* in 1/8 nsec */
    timediff=(long long int)((pos_f-(t0/resolution)) & (zhs-1));
    if (timediff & (zhs>>1)) timediff |= (-zhs); /* do sign extend */
    timediff *=resolution;  
    timediff +=t0;

    /* do washup for fft arrays */
    fftw_destroy_plan(plan1);fftw_destroy_plan(plan2);fftw_destroy_plan(plan3);
    /* do washup for buffers */
    fftw_free(f1);  fftw_free(f2); free(buf1_fast);
    free(buffer1);
 
    /* temporary log of raw data */
    fprintf(stderr,
	    "pfind: pos_f:%d, pos_s:%d, t0:%lld, timediff:%lld, ep:%08x\n",
	    pos_f, pos_s, t0, timediff,startepoch);

    /* report delay */
    /* open log files */
    if (logfname[0]) { /* check if filename is defined */
	loghandle=fopen(logfname,"a");
	if (!loghandle) return -emsg(26);
    } else { loghandle = stdout;}
    
    switch (verbosity_level) {
	case 0:
	    fprintf(loghandle,"%lld\n",timediff);
	    break;
	case 1:
	    fprintf(loghandle,"%lld\t%f\t%f\n",
		    timediff, maxval_f/sigma_f,maxval_s/sigma_s);
	    break;	    
	case 2:
	    fprintf(loghandle,"difference: %lld, sig_f: %f, sig_c:%f\n",
		    timediff, maxval_f/sigma_f,maxval_s/sigma_s);
	    break;
	case 3:
	    fprintf(loghandle,"fine resolution: %.2f nsec\n",resolution/8.0);
	    fprintf(loghandle,"difference: %lld units of 1/8 nsec or %.9f sec\n",
		    timediff,timediff*1.25E-10);
	    fprintf(loghandle,"peak height: fine: %.2f sigma, coarse: %.2f sigma\n",
		    maxval_f/sigma_f,maxval_s/sigma_s);
	    fprintf(loghandle,"counts from channel 1: %d, channel2: %d\n",
		    ecnt1,ecnt2);
	    break;

	default:
	    fprintf(loghandle,"Verbosity level undefined.\n");
    }
    if (logfname[0]) fclose(loghandle);
    

    return 0;
}
