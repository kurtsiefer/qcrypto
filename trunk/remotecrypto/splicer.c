/* splicer.c :  Part of the quantum key distribution software for completing
                the sifting stage on the low count rate side. Description
                see below. Version as of 20070101

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

   program to process the saved results in a type-3 file on side A together
   with a type-4 file from the coincidence/sifting unit on side B. Result is a
   reduced type-3 stream which should contain the raw key information.

   usage:
      splicer [-i type-3 streamfile] | [-d big type-3 directory]
              [-I type-4 streamfile] | [-D type-4 directory] | [-S socket4]
	      [-o out type-3 streamfile] | [-f out type-3 directory] | 
	         [-z socket3]
              [-e start epoch] [-q epochnumber] | [-E cmdpipeline]
	      [-p protocol number]
	      [-k] [-K]
	      [-l logfile] [-V verbosity]


  DATA STREAM OPTIONS:
   -i infile3:      filename of unsifted type-3 packets. Can be a file or a
                    socket and has to supply binary data according to the
		    type-3 data spec from the chopper program.
   -d dir3:         All input type-3 packets are saved into the directory
                    dir3, with the file name being the epoch (filling zero
		    expanded) in hex. Filename is not padded at end.
   -I infile4:      filename of type-4 packets. Can be a file or a socket
                    and has to supply packed sifting index data to the type-4
		    data spec from the costream program.
   -D dir4:         All type-4 packets are saved into the directory dir4, with
                    the file name being the epoch (filling zero expanded)
		    in hex. Filename is not padded at end.
   -o outfile3:     Outfile name for type-3 sifted key packets. This option
                    saves all type-3 packets into a the file/FIFO named
		    outfile3.
   -f outdir3:      All type-3 sifted key packets are saved into the directory
                    outdir4, with the file name being the epoch (filling zero
		    expanded) in hex. Filename is not padded at end.
   -e epoch:        if only directories are given, an epoch index has to be
                    supplied.
   -E cmdpipe:      if this option is supplied, the t4 files are taken from a
                    directory, but processing takes place on files where the
		    name (i.e., epoch number) is piped as text into the pipe
		    specified in this option. If cmdpipe does not exist, it is
		    created.
   -k :             if set, type-3 input streams are removed after consumption
		    if the directory input has been chosen.
   -K :             if set, type-4 input streams are removed after consumption
		    if the directory input has been chosen.

   -p protocol:     Selection of the protocol type. implemented:
                    0: service mode, emits all bits into stream 3 locally
		       for those entries marked in stream 4
		    1: selects basebits from stream 3in which are marked
		       in stream4
   -q epochunum:    number of epocs to be read. When set to 0, it loops
                    forever; this is the default.


  LOGGING & NOTIFICATION:
   -l logfile:   notification target for consumed epochs of type-3 packets.
                 logged are epoch numbers in hex form.
   -L logfile2:  notification target for consumed epochs of type-4 packets.
                 logged are epoch numbers in hex form.
   -m logfile3:  notification target for generated output type-3 packets.
                 log format is specified by -V option
   -V level:     Verbosity level control. controls format for logfile in 
                 the -m option. level is integer, and by default set
                 to 0. The logging verbosity criteria are:
		 level<0 : no output
		 0 : epoch (in plaintext hex). This is default.

History:
   written first specs 21.8.05 chk
   compiles; 29.8.05chk
   completed -l, -L, -m options 26.11.05chk

ToDo:
   checking -in progress, 
   consistent operation with single files?
   check eternal epoch operation in other programs.
   realize different logging options -m, -L

*/

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>


/* default definitions */
#define DEFAULT_VERBOSITY 0
#define FNAMELENGTH 200  /* length of file name buffers */
#define FNAMFORMAT "%200s"   /* for sscanf of filenames */
#define DEFAULT_KILLMODE3 0 /* don't delete stream-1 files */
#define DEFAULT_KILLMODE4 0 /* don't delete stream-2 files */
#define DEFAULT_STARTEPOCH 0
#define DEFAULT_EPOCHNUMBER 0 /* How many epochs to consider; 0: eternal */
#define DEFAULT_PROTOCOL 1 /* standard BB84 */

/* binary buffers */
#define RAW3i_SIZE 1500000  /* more than enough? */
#define RAW4i_SIZE  4000000   /* plenty */
#define RAW3o_SIZE  4000000   /* should be enough */

/* ---------------------------------------------------------------------- */

/* buffer headers */
typedef struct rawevent {unsigned int cv; /* most significan word */
    unsigned int dv; /* least sig word */} re;
#define RAW_PATTERNMASK 0xf /* get the four detectors */

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
typedef struct header_3 {/* header for type-3 stream packet */
    int tag;
    unsigned int epoc;
    unsigned int length;
    int bitsperentry; 
} h3;

typedef struct header_4 {/* header for type-4 stream packet */
    int tag;
    unsigned int epoc;
    unsigned int length;
    int timeorder;
    int basebits;
} h4;

#define TYPE_1_TAG 1
#define TYPE_1_TAG_U 0x101
#define TYPE_2_TAG 2
#define TYPE_2_TAG_U 0x102
#define TYPE_3_TAG 3
#define TYPE_3_TAG_U 0x103
#define TYPE_4_TAG 4
#define TYPE_4_TAG_U 0x104

#define TYPE_4_ENDWORD 1

/* ---------------------------------------------------------------------- */
/* protocol definitions */

typedef struct protocol_details_C { /* used in splicer program */
    int expected3ibits; /* bits expected from local bit source */
    int expected4ibits; /* bits expected from remote bit source */
    int transmittedbits; /* bits which should end up in target file */
    int decsize; /* size of an array containing the outpattern3, where
		    the parameter is the ORed version of the local bits
		    from stream 3in, and the bits received from stream4in,
		    shifted by exected3ibits to the left. This size should be
		    1<<(expected3bits+expected4bits). */
    void (*filltable)(unsigned int*); /* helper function to fill this array. Has to be
			        called in the beginning */
} pd_C;
#define PROTOCOL_MAXINDEX 1
void FILL_TABLE_PROTO0(unsigned int *t) {
    int i;
    for (i=0;i<256;i++) 
	t[i]=(i>>4)|((i&0xf)<<4); /* nibble swap */
    return;
}
void FILL_TABLE_PROTO1(unsigned int *t) {
    t[0]=0;t[1]=1;
    return;
}
struct protocol_details_C proto_table[] = {
    {/* service protocol. emits all bits in stream 3i and 4i into the outword.
	the 3i bits end up in bits 4..7, the 4i inbits in bits0..3. This gives
	the same service files on both sides. It expects 4 bits from stream 3i
	and 4i. */
	4,4,8,256,
	&FILL_TABLE_PROTO0},
    {/* standard BB84 protocol. expects 1 bit from stream 3i, and nothing from
      stream 4i. reflects the inbit to the outbit. */
	1,0,1,2,
	&FILL_TABLE_PROTO1},
};


/* ---------------------------------------------------------------------- */

/* error handling */
char *errormessage[] = {
  "No error.",
  "Error reading in verbosity argument.", /* 1 */
  "Error reading file/directory name for type-3 input packets.",
  "Error reading file/directory name for type-4 input packets.",
  "Error reading file/directory name for type-3 output packets.",
  "duplicate definition of type-3 infile.", /* 5 */
  "duplicate definition of type-4 infile.",
  "duplicate definition of type-3 outfile.",
  "error parsing startepoch.",
  "error parsing epoch number.",
  "Error parsing protocol index.", /* 10 */
  "protocol out of range (0..1)",
  "error parsing one of the logfile names.",
  "Cannot malloc stream-3i buffer.",
  "Cannot malloc stream-4i buffer.",
  "Cannot malloc stream-3o buffer.", /* 15 */
  "Error opening logfile.",
  "error opening source stream 3", 
  "error opening source stream 4", 
  "error opening target stream 3", 
  "No content reading input stream 3.", /* 20 */
  "General I/O error reading stream 3", 
  "incomplete read on stream 3.",
  "wrong stream type detected when looking for stream-3.",
  "stream 3 inconsistency detected.",
  "mismatch between expected and transmitted bits in stream 3.", /* 25 */
  "No content reading stream 4.",
  "General I/O error reading stream 4.",
  "incomplete read on stream 4.",
  "wrong stream type detected when looking for stream-4.",
  "stream 4 inconsistency detected.",  /* 30 */
  "mismatch between expected and transmitted bits in stream 4.",
  "Cannot write header of stream-3",
  "Error writing data to stream-3",
  "error removing stream 3 file.",
  "error removing stream 4 file.", /* 35 */
  "cannot malloc output table",
  "index range exceed using stream-4 index in stream-3 array.",
  "error reading command pipeline",
  "error opening command pipeline",
  "cannot stat command pipeline", /* 40 */
  "cmdpipe is not a FIFO",
  "cannot read current epoch from pipe",

};
int emsg(int code) {
  fprintf(stderr,"%s\n",errormessage[code]);
  return code;
};

int openmode[3] = {O_RDONLY,O_RDONLY, /* modes for input streams */
		   O_WRONLY | O_TRUNC | O_CREAT /* outstream 3 */
};

#define FILE_PERMISSIONS 0644  /* for all output files */

/* global variables for IO handling */
int verbosity_level = DEFAULT_VERBOSITY;
/* handle index: 0: stream3 input, 1: stream4 input, 2: stream3output,
   4: cmdpipeline input */
char fname[4][FNAMELENGTH]={"","","",""}; /* stream files / cmd pipeline */
char ffnam[3][FNAMELENGTH+10]; /* combined dir/filenames */
int typemode[3]={0,0,0}; /* 0: no mode defined. other types:
			    1: single file, 2: directory save, ... */
int killmode[2] = {DEFAULT_KILLMODE3,
		   DEFAULT_KILLMODE4 }; /* if !=1, delete infile after use */
FILE* loghandle[3]; /* index 0: cnsmd t3, 1: cnsmd t4, 2: made rawk */
char logfname[3][FNAMELENGTH]={"","",""};
int handle[3]; /* global handles for packet streams */
unsigned int current_ep;
struct header_3 head3i; /* infile header */
struct header_4 head4i; /* infile header */
struct header_3 head3o; /* outfile header */
int expected3bits, expected4bits;

int get_stream_3(void *buffer, int handle, int maxsize,
		 struct header_3 *head) {
    int retval;
    int bytenum;
    struct header_3 *h; /* for local storage */
    retval=read(handle,buffer,maxsize);
    if (!retval) return 20; /* nothing available */
    if (!(retval+1)) return 21; /* other error */
    if (retval<(int)sizeof(struct header_3)) return 22; /* incomplete read */
    h=(struct header_3 *)buffer; /* at beginning of stream */
    /* consistency check at end */
    if ((h->tag!=TYPE_3_TAG) && (h->tag!=TYPE_3_TAG_U)) return 23;
    bytenum= (h->length*h->bitsperentry+7)/8+sizeof(struct header_3);
    bytenum = (bytenum>>2) + ((bytenum &3)?1:0); /* words */
    if (bytenum*4!=retval) return 24;
    /* protocol bit match? */
    if (h->bitsperentry != expected3bits) return 25;
    *head=h[0];
return 0;
}
/* index file */
int get_stream_4(void *buffer, int handle, int maxsize,
		 struct header_4 *head, int *realsize) {
    int retval;
    int bitnum;
    struct header_4* h;
    
    retval=read(handle,buffer,maxsize);

    if (!retval) return 26; /* nothing available */
    if (!(retval+1)) return 27; /* other error */
    if (retval<(int)sizeof(struct header_4)) return 28; /* incomplete read */
    h=(struct header_4 *)buffer; /* at beginning of stream */
    /* consistency check on length and tag */
    if ((h->tag!=TYPE_4_TAG) && (h->tag!=TYPE_4_TAG_U)) return 29;

    /* length check; assumes one termination pattern (including bit pattern)
       for termination. check specs if this is ok? */
    if (h->length) {
	bitnum=(retval-sizeof(struct header_4))*8/(h->length+1)
	    - h->basebits-h->timeorder;
	if ((bitnum<0) | (bitnum >32)) return 30;
    }
    /* protocol bit match? */
    if (h->basebits != expected4bits) return 31;
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

/* function to eventually open a stream. params: index, epoch */
int openstream(int i, unsigned int ep) {
    switch (typemode[i]) {
	case 2: /* file in directory */
	    strncpy(ffnam[i], fname[i], FNAMELENGTH);
	    atohex(&ffnam[i][strlen(ffnam[i])],ep);
	    handle[i]=open(ffnam[i],openmode[i],FILE_PERMISSIONS);
	    if(-1==handle[i]) {
		fprintf(stderr,"handle %d named >>%s<< failed.",
			i,ffnam[i]);
		return 1;
	    }
	    break;
    }
    return 0;
}

int main (int argc, char *argv[]) {
    unsigned int startepoch = DEFAULT_STARTEPOCH; /* epoch to start with */
    unsigned int epochnumber = DEFAULT_EPOCHNUMBER; /* # of epochs to read  */
    int proto_index = DEFAULT_PROTOCOL; /* defines which proto is used */
    long long int se_in; /* for entering startepoch both in hex and decimal */
    char *buffer3i, *buffer4i, *buffer3o; /* stream buffers */

    int realsize4i; /* for processing stream 4 */
    unsigned int *pointer4;
    unsigned int diff4,tindex,opatt4;
    unsigned int readword4,emergency_break,pattern4,patternmask4,diff4_bitmask;
    int resbits4;
    int type4bitwidth,type4datawidth,processed_4events,bitstoread4;
    
    int k3i,n3i,type3ibits,u3i;
    unsigned int pattern3i, patternmask3i;
    unsigned int *pointer3i;
    int p3mask1[32],p3sh1[32],p3mask2[32],p3sh2[32],p3sh0[32],p3dec[32];
    int stream3imaxindex; /* for input consistency check */

    unsigned int pattern3o;
    unsigned int sendword3;
    int resbits3o,type3odatawidth,index3o;
    unsigned int *outbuf3o, *o3_lookup;
    
    int opt,i,j,retval;
    unsigned int ju; /* wherever it is needed */

    int cmdmode = 0;  /* pipeline mode if !=0 */
    FILE *cmdhandle = NULL;
    struct stat cmdstat; /* for probing pipe */

    opterr=0; /* be quiet when there are no options */
    while ((opt=getopt(argc, argv, "V:i:d:I:D:o:f:e:q:p:kKl:E:L:m:")) != EOF) {
	i=0; /* for setinf names/modes commonly */
	switch (opt) {
	    case 'V': /* set verbosity level */
		if (1!=sscanf(optarg,"%d",&verbosity_level)) return -emsg(1);
		break;
		/* a funky way of parsing all file name options together.
		   i contains the stream in the two lsb, and the mode in the
		   msb. */
	    case 'f': i++; /* stream 3out, directory */
	    case 'D': i++; /* stream 4in, directory */
 	    case 'd': i++; /* stream 3in, directory */
		i++;
 	    case 'o': i++; /* stream 3out, file */
 	    case 'I': i++; /* stream 4in, file */
 	    case 'i':      /* stream 3in, file */
		j=(i&3); /* stream number (ranges from 0 to 2)*/
		if (1!=sscanf(optarg,FNAMFORMAT,fname[j])) return -emsg(2+j);
		fname[j][FNAMELENGTH-1]=0;   /* security termination */
		if (typemode[j]) return -emsg(5+j); /* already defined mode */
		typemode[j]=(i&4?2:1);
		break;
	    case 'e': /* read startepoch */
		if (1!=sscanf(optarg,"%lli",&se_in)) return -emsg(8);
		startepoch=se_in & 0xffffffff;
		break;
	    case 'E':  /* command pipeline */
		if (1!=sscanf(optarg,FNAMFORMAT,fname[3])) return -emsg(38);
		cmdmode=1; 
		break;
	    case 'q': /* read epoch number */
		if (1!=sscanf(optarg,"%d",&epochnumber)) return -emsg(9);
		break;
	    case 'p': /* protocol index */
		if (1!= sscanf(optarg,"%i",&proto_index)) return -emsg(10);
		if ((proto_index<0) || (proto_index>PROTOCOL_MAXINDEX))
		    return -emsg(11);
		break;
	    case 'k': case 'K':/* kill mode stream 1 and 2 */
		killmode[opt=='k'?0:1]=1;
		break;
	    case 'm': i++; /* generated type3 raw keys */
	    case 'L': i++; /* filename for consumed type4 packets */
	    case 'l': /* read logfile name for consumed t3 intermed packets */
		if (sscanf(optarg,FNAMFORMAT,logfname[i]) != 1)
		    return -emsg(12);
		logfname[i][FNAMELENGTH-1]=0;  /* security termination */
		break;
	}
    }

    /* check argument consistency */
    if (cmdmode) { /* open command pipeline */
	if (stat(fname[3],&cmdstat)) return -emsg(40);
	if (!S_ISFIFO(cmdstat.st_mode)) return -emsg(41);
	if (!(cmdhandle=fopen(fname[3],"r+"))) return -emsg(39);
    }

    /* allocate input and output buffers */
    if (!(buffer3i=(char*)malloc(RAW3i_SIZE))) return -emsg(13);
    if (!(buffer4i=(char*)malloc(RAW4i_SIZE))) return -emsg(14);
    if (!(buffer3o=(char*)malloc(RAW3o_SIZE))) return -emsg(15);

    /* prepare protocol specific stuff */
    type3odatawidth=proto_table[proto_index].transmittedbits;
    expected3bits=proto_table[proto_index].expected3ibits;
    expected4bits=proto_table[proto_index].expected4ibits;
    /* fill outword table */
    o3_lookup=(unsigned int *)malloc(sizeof(int)*
			    proto_table[proto_index].decsize);
    if (!o3_lookup ) return -emsg(36);
    proto_table[proto_index].filltable(o3_lookup);

    type3ibits=expected3bits;
    patternmask3i=(1<<type3ibits)-1;
    pointer3i=(unsigned int *)(buffer3i+sizeof(struct header_3));
    for (i=0;i<32;i++) { /* populate shift mask index */
	p3mask1[i]=(1<<(32-i))-1;
	p3sh1[i]=type3ibits-32+i;
	p3sh0[i]=-p3sh1[i];
	p3dec[i]=(i+type3ibits)<33?1:0;
	p3sh2[i]=64-type3ibits-i;
	p3mask2[i]=(-1<<p3sh2[i]);
    }
    

    /* open logfile stream(s) */
    for (i=0;i<3;i++) {
	if (logfname[i][0]) { /* check if filename is defined */
	    loghandle[i]=fopen(logfname[i],"w");
	    if (!loghandle[i]) return -emsg(16);
	}
    }

    /* evtl. open source/destination stream files */
    for (i=0;i<3;i++) {
    	switch (typemode[i]) {
	    case 1: /* file in directory */
		handle[i]=open(fname[i],openmode[i],FILE_PERMISSIONS);
		if(-1==handle[i]) return -emsg(17+i);
		break;
	}
    }


    if (cmdmode) { /* load initial epoch */
	if (1!=fscanf(cmdhandle,"%x",&current_ep)) return -emsg(42);
    } else {
	current_ep=startepoch;
    }
    /* main digest loop */
    do {
	/* eventually open input stream 3 */
	if (openstream(0,current_ep)) return -emsg(17);
	/* load instream-3 */
        retval=get_stream_3(buffer3i,handle[0],RAW3i_SIZE,&head3i);
	if (retval) return -emsg(retval);
	/* eventually close input stream 3 */
	if(typemode[0]==2) close(handle[0]);
	/* consistency_check */
	stream3imaxindex=(head3i.length*head3i.bitsperentry+31)/32-1;
	/* eventually open input stream 4 */
	if (openstream(1,current_ep)) return -emsg(18);
	/* load instream-4 */
	retval=get_stream_4(buffer4i,handle[1],RAW4i_SIZE,&head4i,&realsize4i);
	if (retval) return -emsg(retval);
	/* eventually close input stream 4 */
	if(typemode[1]==2) close(handle[1]);
	/* consistency_check */

	/* prepare outstream-3 */
	head3o.tag=(head4i.tag==TYPE_4_TAG_U)?
	    TYPE_3_TAG_U:TYPE_3_TAG; /* same style */
	head3o.epoc=current_ep;
	head3o.length=0;
	head3o.bitsperentry=type3odatawidth;

	/* prepare parsing instream-4 elements */
	tindex=0; /* initial value */
	pointer4=(unsigned int *)(buffer4i+sizeof(struct header_4));
	ju=0;readword4=pointer4[ju++]; /* prepare read buffer */
	resbits4=32;
	type4bitwidth=head4i.timeorder; type4datawidth=head4i.basebits;
	bitstoread4=type4bitwidth+type4datawidth;
	emergency_break=
	    (realsize4i-sizeof(struct header_4))/sizeof(unsigned int);
	patternmask4=(1<<type4datawidth)-1;
	diff4_bitmask=(1<<type4bitwidth)-1;
	processed_4events=0; /* processed events */

        sendword3=0;
	outbuf3o=(unsigned int *)buffer3o;
	resbits3o=32;index3o=0;

	do { /* go through buffer */
	    if (resbits4>=bitstoread4) {
		diff4=(readword4>>(resbits4-bitstoread4));
		resbits4-=bitstoread4;
		if (!resbits4) {readword4=pointer4[ju++];resbits4=32;}
	    } else {
		resbits4=bitstoread4-resbits4;
		diff4=readword4<<resbits4;
		readword4=pointer4[ju++];
		resbits4=32-resbits4;
		diff4=(diff4 | (readword4>>resbits4));
	    }
	    pattern4= (diff4 & patternmask4);
	    diff4>>=type4datawidth;
	    /* we have a time difference word now in tdiff */
	    if (diff4 &= diff4_bitmask) { /* check for exception */
		/* test for end of stream */
		if (diff4==1) break; /* exit digest routine for this stream */
	    } else {
		/* read in complete difference */
		diff4=readword4<<(32-resbits4);
		readword4=pointer4[ju++];
                /* catch shift 'feature' - normal */
		if (resbits4 & 0x1f) diff4 |= readword4>>resbits4;
		opatt4=pattern4;pattern4=diff4&patternmask4;
		diff4 >>=type4datawidth;
		diff4 |=  (opatt4<<(32-type4datawidth));
	    }
	    /* we now have a valid difference */
	    tindex +=diff4-2; /* correction for index compensation */


	    /* extract pattern from 3i */
	    k3i=tindex*type3ibits;n3i=k3i%32;/* shift info sourceword */
	    if ( (u3i=k3i/32)>stream3imaxindex) return -emsg(37);
	    if (p3dec[n3i]) { /* contained in one word */
		pattern3i=(pointer3i[k3i/32]>>p3sh0[n3i])
			       & patternmask3i;
	    } else {
		pattern3i  = (pointer3i[k3i/32]  & p3mask1[n3i]) << p3sh1[n3i];
		pattern3i |= (pointer3i[k3i/32+1]& p3mask2[n3i]) >> p3sh2[n3i];
	    }
	    /* we now have the pattern in pattern3i */

	    /* type-3 stream filling */
	    pattern3o=o3_lookup[pattern3i 
				| (pattern4<<type3ibits)]; /* out pattern */
	    if (resbits3o>=type3odatawidth) {
		sendword3 |= (pattern3o << (resbits3o-type3odatawidth));
		resbits3o = resbits3o-type3odatawidth;
		if (resbits3o==0) { 
		    outbuf3o[index3o++]=sendword3;
		    sendword3=0;resbits3o=32;
		}
	    } else {
		resbits3o=type3odatawidth-resbits3o;
		sendword3 |= (pattern3o >> resbits3o);
		outbuf3o[index3o++]=sendword3;
		resbits3o=32-resbits3o;
		sendword3=pattern3o << resbits3o;
	    }
	    processed_4events++;
	} while (ju<=emergency_break); /* make sure to eat up rest properly */
	
	/* output outstream-3 */
	head3o.length=processed_4events;
	if (resbits3o<32) outbuf3o[index3o++]=sendword3; /* last word */
	
	/* eventually open output stream 3 */
	if (openstream(2,current_ep)) return -emsg(19);
	
	/* write header 3 */
	retval= write(handle[2],&head3o,sizeof(struct header_3));
	if (retval!=sizeof(struct header_3)) 
	    return -emsg(32); /* write head err */
	i=index3o*sizeof(unsigned int);
	retval=write(handle[2],outbuf3o,i);
	if (retval!=i) return -emsg(33); /* write error buffer */
	
	/* eventually close stream 3 */
	if (typemode[2]==2) close(handle[2]);

	/* eventually remove instreams */
	for (i=0;i<2;i++) if (killmode[i] && (typemode[i]==2)) {
	    if (unlink(ffnam[i])) return -emsg(34+i);
	}
	
        /* do logging */
	for (i=0;i<3;i++) {
	    if (logfname[i][0]) {
		switch(verbosity_level) {
		    case 0: /* print only epoch */
			fprintf(loghandle[i],"%08x\n",current_ep);
			break;
		    case 1: /* epoch, resulting keybits */
			fprintf(loghandle[i],"%08x\t%d\n",
				current_ep,processed_4events);
			break;
		    case 2: /* same w text */
			fprintf(loghandle[i],"epoch: %08x, final events: %d\n",
				current_ep,processed_4events);
			break;
		}
		/* fprintf(loghandle[i],"bla\n"); */
		fflush(loghandle[i]);
	    }
	}
	

	if (cmdmode) { /* wait for next epoch */
	    if (1!=fscanf(cmdhandle,"%x",&current_ep)) return -emsg(42);
	} else {
	    current_ep++; /* next epoch */
	}
    } while ((current_ep<startepoch+epochnumber) || (!epochnumber));
    /* return benignly */
    
    /* evtl. close stream files */
    for (i=1;i<3;i++) 
	if (1== (typemode[i])) close(handle[i]); /* single file */

    for (i=0;i<3;i++) if (logfname[i][0]) fclose(loghandle[i]);
    /* free buffers */
    free(buffer3i);free(buffer4i);free(buffer3o);
    return 0;
}
