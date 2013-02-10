/* chopper.c : Part of the quantum key distribution software for partitioning
               timestamp data and compressing timing information. Description
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

   program to digest the binary input from a timestamp card, separate
   it into sections corresponding to one epoc, and emit packets for
   sifting/coincidence purpose both for transmission over the classical
   channel and for local storage for later key usage.

   The file formats emitted are tagged compressed packages of filetype 2 and 3
   according to the crypto transfer file format spec whitepaper.
   
   status: runs over 54k epochs on feb 7 2006
   added -V4 option for complex logging 21feb06chk not tested yet

   usage: chopper [-i infilename] 
                  -O outfilename2 | -D filedir2 | -S socket2
                  -o outfilename3 | -d outfiledir3 | -s socket3
		  [-l logfile] [-F ] [-V verbosity]
		  [-U | -L]
		  [-p num] [-q depth] [-Q filterconst]
		  [-m maxtime]
	 
   implemented options:

 DATA STREAM OPTIONS:
   -i infilename:   filename of source events. Can be a file or a socket
                    and has to supply binary data according to the raw data
		    spec from thetimestamp unit.

   -O fname2:       Outfile name for type 2 compressed sifting time files.
                    This option saves all type 2 packets into a the file/FIFO
		    named fname2
   -D dir2:         All type-2 packets are saved into the directory dir2, with
                    the file name being the epoch (filling zero expanded)
		    in hex. Filename is not padded at end.
   -o fname3:       same as option -O, but for type-3 files
   -d dir3:         same as option -d, but for type-3 files
  
 ENCODING OPTIONS:
   -U:      universal epoch; the epoch is not only derived from the timestamp
            unit digits, but normalized to unix time origin. This needs the
	    timestamp unit to emit event data with an absolute time tag. 
	    For this to work, the received data cannot be older than xxx hours,
	    or an unnoted ambiguity error will occur.
   -L:      local timestamps only. The epoch is calculated from the
            unmodified timestamp info as received from the unit. This is the
	    default.
   -q depth:Number of bits used to compress the timing data. default is 17,
            which should be optimal for ... kevents/sec.
   -Q num:  filter time constant for bitlength optimizer. The larger the
            num, the longer the memory of the filter. for num=0, no change will
	    take place. This is also the default.

 LOGGING & NOTIFICATION
   -l logfile:   Each emitted epoch packet index is logged into this file. The
                 verbosity level controls the granularity of details logged.
		 If no filename is specified, logging is sent to STDOUT.
   -V level:     Verbosity level control. level is integer, and by default set
                 to 0. The logging verbosity criteria are:
		 level<0 : no logging
		 0 : log only epoc number (in hex)
		 1 : log epoch, length without text
		 2 : log epoch, length with text
		 3 : log epoch, length, bitlength with text
		 4 : log epoch, detector histos without text
   -4            sets the number of detectors to be logged to 4 (default)
                 in service mode. Has no effect in crypto modes
   -6            sets the number of detectors to be logged to 6. This option
                 has only an effect in service mode
   -F            flushmode. If set, the logging info is flushed after every
                 write. useful if used for driving the transfer deamon.
   -e debugfile  choose a file for debug logging. This used to be hardcoded to
                 the file /tmp/cryptostuff/chopdebug, but is turned off for use
		 with other applications.

 PROTOCOL OPTION
   -p num:       select protocol option. defines what transmission protocol
                 is run by selecting what event bits are saved in which
		 stream. option 1 is default.
		 0: service protocol. both type-2 stream and type-3 stream
		    contain the raw detector information.
		 1: BB84 standard protocol. The type-2 stream contains one bit
		    of basis information, the type-3 stream one bit of
		    value information. The detector sequence is hardcoded in
		    the header.
		 2: rich BB84. As before, but two  bits are transmitted. if the
		    msb is 0, the lsb has BB84 meaning, if msb is 1, a multi-
		    or no-coincidence event was recorded (lsb=1), or a pair
		    coincidence was detected (lsb=0).
                ---------modifications for device-independent -------- 
                 3: six detectors connected to this side, used for the
                    device-independent mode. three transmitted bits, indicating
		    bell basis or key basis
		 4: four detectors connected to this side, device-indep
		    operation. only time is transmitted.
		---------modifications to BC protocol-----------------
		 5: Like 1, but no basis is transmitted, but basis/result
		    kept in local file

		 
PROTECTION OPTION
   -m maxnum:    maximum time for a consecutive event to be meaningful. If
                 the time difference to a previous event exceeds this time,
		 the event is discarded assuming it has to be an error in the
		 timing information. Default set to 0, which corresponds to
		 this option being switched off. Time units is in microseconds.

 History:
   specs & coding started   13.08.2005 chk
   compiles, first tests: type-2 format&content , type-3 length, 
   compression servo   21.8.05 chk
   detects negative time differences and works with pfind, costream
   28.8.05chk
   added flushmode 19.9.05chk
   !!!!!!!modified input section select etc
   added -m option 18.1.06 chk
   tried to fix rollover problem in difference test 060306chk
   merge with deviceindep protocol set 29.7.09chk
   started to extend for bc protocol

 To Do:
   populate lookup tables -ok?
   log all data  -ok?
   log performance data  --?
   review emty input file issue - currently, an emty input stream terminates
   the program.
   check buffer sizes
   remove bitstosend calc from main loop
   change stream-2 endword definition in filespec and program
   cleanup of debug logging and fishyness

*/
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>


/* default definitions */
#define DEFAULT_VERBOSITY 0
#define FNAMELENGTH 200  /* length of file name buffers */
#define FNAMFORMAT "%200s"   /* for sscanf of filenames */
#define DEFAULT_UEPOCH 0   /* choose no universal epoch option */
#define INBUFENTRIES 1024 /* max. elements in input buffer */
#define RETRYREADWAIT 500000 /* sleep time in usec after an empty read */
#define DEFAULT_STATEMASK 0xf /* take last four bits of dv */
#define TYPE2_BUFFERSIZE (1<<20)  /* should be sufficient for 700kcps events */
#define TYPE3_BUFFERSIZE (1<<18)  /* plenty for 700 kcps */
#define DEFAULT_FIRSTEPOCHDELAY 10 /* first epoch delay */
#define DEFAULT_PROTOCOL 1 /* standard BB84 */
#define DEFAULT_BITDEPTH 17 /* should be optimal for 100 kevents/Sec */
#define DEFAULT_FILTERCONST 0  /* no adaptive bitwidth  */
#define FILE_PERMISSONS 0644  /* for all output files */
#define DEFAULT_FLUSHMODE 0 /* switched off by default */
#define MAXIMAL_FISHYNESS 5 /* how many out-ot-time events to detect */
#define DEFAULT_IGNORECOUNT 0 /* how many events to ignore initially */
#define DEFAULT_MAXDIFF 0 /* maximum allowable time between events */

typedef struct rawevent {unsigned int cv; /* most significan word */
    unsigned int dv; /* least sig word */} re;

/* protocol definitions */
typedef struct protocol_details {
    int bitsperentry2;
    int bitsperentry3;
    int detectorentries; /* number of detectorentries; 16 for 4 detectors;
			    this value -1 is used as bitmask for status */
    int numberofdetectors; /* to cater logging purposes for more than
			      4 detectors */
    int pattern2[16];
    int pattern3[16];} pd;

#define PROTOCOL_MAXINDEX 5

static struct protocol_details proto_table[] = {
  {/* protocol 0: all bits go everywhere */
    4,4,16,4,
    {0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf}, /* pattern 2 */
    {0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf} /* pattern 3 */
  },
  {/* protocol 1: standard BB84. assumed sequence:  (LSB) V,-,H,+ (MSB);
      HV basis: 0, +-basis: 1, result: V-: 0, result: H+: 1 */
    1,1,16,4,
    {0,0,1,0, 0,0,0,0, 1,0,0,0, 0,0,0,0}, /* pattern 2 : basis */
    {0,0,0,0, 1,0,0,0, 1,0,0,0, 0,0,0,0} /* pattern 3 : result */
  },
  {/* protocol 2: rich BB84. assumed sequence:  (LSB) V,-,H,+ (MSB);
      HV basis: 0, +-basis: 1, result: V-: 0, result: H+: 1 
      if an illegal pattern was detected, a pair info pattern (2) or a
      multi/no coincidence pattern (3) is recorded*/
    2,2,16,4,
    {3,0,1,2, 0,2,2,3, 1,2,2,3, 2,3,3,3}, /* pattern 2 : basis */
    {3,0,0,2, 1,2,2,3, 1,2,2,3, 2,3,3,3} /* pattern 3 : result */
  },
  {/* protocol 3: device-independent, six-detectors @chopper. assumed sequence:
      V+22.5,-22.5, H+22.5, +45+22.5, H, V (!!!CHECK SPECS!!!)
      illegal pattern: value 5, bell result: value 0-3, key result: value 4
      the local file keeps the original detector combination */
    3,4,16,6,
    {5,0,1,4, 2,5,4,5, 3,5,5,5, 5,5,5,5}, /* pattern2: bell/key */
    {0,1,2,3, 4,5,6,7, 0x8,0x9,0xa,0xb, 0xc,0xd,0xe,0xf} /* local: orig */
  },
  {/* protocol 4: device-independent, four detectors @chopper. assumed sequence:
      V,-, H, + (!!!CHECK SPECS!!!)
      illegal pattern: value 0, otherwise 1.
      the local file keeps the original detector combination */
    1,4,16,4,
    {0,1,1,0, 1,0,0,0, 1,0,0,0, 0,0,0,0}, /* pattern2: legal (1) /illegal (0)*/
    {0,1,2,3, 4,5,6,7, 0x8,0x9,0xa,0xb, 0xc,0xd,0xe,0xf} /* local: orig */
  },
  {/* protocol 5: 'reduced BB84. assumed sequence:  (LSB) V,-,H,+ (MSB);
      result: V: 0, -: 2, H: 1, +: 3 such that bit 0 is result, bit 1 basis */
    0,2,16,4,
    {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}, /* pattern 2 : send nothing */
    {0,0,2,0, 1,0,0,0, 3,0,0,0, 0,0,0,0} /* pattern 3 : result */
  },
};


/* error handling */
char *errormessage[] = {
  "No error.",
  "Error reading in verbosity argument.", /* 1 */
  "Error reading in infile name.",
  "Error reading file/directory name for type-2 packets.",
  "duplicate definition of type-2 file.",
  "Error reading file/directory name for type-3 packets.", /* 5 */
  "duplicate definition of type-3 file.",
  "Error reading logfile name.",
  "no type-2 stream channel defined",
  "no type-3 stream channel defined",
  "Error opening type-2 packet destination", /* 10 */
  "Error opening type-3 packet destination", 
  "Error opening input stream source",
  "Cannot malloc input buffer.",
  "End of input stream upon first read",
  "unspecified Input read error", /* 15 */
  "error terminating streams for running epoc",
  "error preparing type-2 and type-3 steams for new epoch.",
  "cannot malloc stream 2 buffer.",
  "cannot malloc stream 3 buffer.",
  "cannot write type-2 header", /* 20 */
  "cannot write type-2 data",
  "cannot write type-3 header",
  "cannot write type-3 data",
  "empty error message to fill up list",
  "error reading protocol number", /* 25 */
  "protocol index out of range",
  "cannot malloc pattern table",
  "error reading bit depth",
  "bit depthout of range (4..32)",
  "error reading filter constant in -Q option", /* 30*/
  "filter constant in -Q option out of range.",
  "cannot open logfile.",
  "error reading ignorecount argument",
  "ignoecounts  less than 0",
  "error reading max time difference value (must be >=0)", /* 35 */
  "Error reading debug file name.",
  "cannot open debug log file",
};

int emsg(int code) {
  fprintf(stderr,"%s\n",errormessage[code]);
  return code;
};

/* global variables for IO handling */
int handle1,handle2,handle3; /* in and out file handles */
FILE* loghandle; /* for log files */
FILE* debuglog;
int index2,index3; /* index in outbuffer fields */
unsigned int *outbuf2, *outbuf3; /* output buffer pointers */
unsigned int sendword2, sendword3; /* bit accumulators */
int resbits2, resbits3;  /* how many bits are not used in the accumulators */
int thisepoch_converted_entries; /* for output buffers */
int type2bitwidth = DEFAULT_BITDEPTH; /* for time encoding */
int type2bitwidth_long=DEFAULT_BITDEPTH<<8; /* adaptive filtering */
unsigned int tdiff_bitmask;  /* detecting exceptopn words */
int bitstosend2; /* how many bits in type-2 streams */
int type2datawidth,type3datawidth;
int filterconst = DEFAULT_FILTERCONST; /* for compression tracking */
int verbosity_level = DEFAULT_VERBOSITY;
char fname2[FNAMELENGTH]="";
char fname3[FNAMELENGTH]="";
char logfname[FNAMELENGTH]="";
char debugfname[FNAMELENGTH]="";
int type2mode = 0; /* no mode defined. other tpyes:
		      1: single file, 2: directory save, ... */
int type3mode = 0; /* same as for type2 files */
int proto_index = DEFAULT_PROTOCOL; /* defines which proto is used */
int uepoch= DEFAULT_UEPOCH; /* universal epoch mode 0: no, 1: yes */
int flushmode = DEFAULT_FLUSHMODE; /* if !=0, flush after every write */
int sum[7] ; /* for keeping detector sums */
int sumindex[7] = {0xf, 1,2,4,8,3,6}; /* for logging. last two for 6 det */
int detcnts[16]; /* detector counts */
int numberofdetectors = 4; /* default number of detctors */

/* structures for output buffer headers */
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
#define TYPE_1_TAG 1
#define TYPE_1_TAG_U 0x101
#define TYPE_2_TAG 2
#define TYPE_2_TAG_U 0x102
#define TYPE_3_TAG 3
#define TYPE_3_TAG_U 0x103
#define TYPE_4_TAG 4
#define TYPE_4_TAG_U 0x104

struct header_2 head2; /* keeps header for type 2 files */
struct header_3 head3; /* keeps header for type 3 files */

/* lookup table for correction */
#define PL2 0x20000  /* + step fudge correction for epoc index mismatch */
#define MI2 0xfffe0000 /* - step fudge correction */
unsigned int overlay_correction[16]= {0,0,0,PL2,  0,0,0,0,
				      MI2,0,0,0,  MI2,MI2,0,0};
/* opening routine to target files & epoch construction */
int open_epoch(unsigned int te) {
    unsigned long long aep,tim;
    unsigned int aepoc,finalepoc;
    int overlay;

    /* determine current epoc from raw epoc */
    if (uepoch) { /* take universal epoch */
	tim=time(NULL);
	aep=(tim*1953125)>>20; /* time in epocs */
	aepoc = (unsigned long) (aep & 0xffffffff);
	overlay = ((aepoc >>15) & 3 )| /* from absolute epoc */
	    ((te >>13) & 0xc); /* from timestamp epoc */
	finalepoc = (aepoc & 0xfffe0000) + te + overlay_correction[overlay];
	if ((debuglog) && overlay_correction[overlay])  {
	    fprintf(debuglog,
		    "ovrly corr; tim: %lld, te: %08x, overlay: %08x\n",
		    tim,te,overlay);
	    fflush(debuglog);
	}
    } else {
	finalepoc = te;
    }
    
    /* populate headers preliminary */
    head3.tag = uepoch?TYPE_3_TAG_U:TYPE_3_TAG; head3.length = 0;
    head3.epoc = finalepoc; head3.bitsperentry = type3datawidth;

    head2.tag = uepoch?TYPE_2_TAG_U:TYPE_2_TAG; head2.length = 0;
    head2.timeorder = type2bitwidth; head2.basebits = type2datawidth;
    head2.epoc = finalepoc;
    head2.protocol = proto_index;


    /* initialize output buffers and temp storage*/
    index2=0;sendword2=0;resbits2=32;
    index3=0;sendword3=0;resbits3=32;
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

#define TYPE2_ENDWORD 1  /* shortword to terminate a type 2 stream */
/*  int  log_correcttable[] = 
  {35, 37, 38, 39, 41, 42, 43, 44, 45, 46, 47, 47, 48, 49, 50, 51}; */
/* flush output buffers and submit files */
int close_epoch() {
    char ffnam[FNAMELENGTH+10];
    int retval,i,optimal_width,j;
    unsigned int average_distance,t1;

    if (!thisepoch_converted_entries) return 0; /* no data collected */

    /* finish stream 2 entries */
    t1 = TYPE2_ENDWORD<<type2datawidth;     /* add closing word */
    /* save timing and transmit bits */
    if (resbits2>=bitstosend2) {
	sendword2 |= (t1 << (resbits2-bitstosend2));
	resbits2 = resbits2-bitstosend2;
	if (resbits2==0) { 
	    outbuf2[index2++]=sendword2;
	    sendword2=0;resbits2=32;
	}
    } else {
	resbits2=bitstosend2-resbits2;
	sendword2 |= (t1 >> resbits2);
	outbuf2[index2++]=sendword2;
	resbits2=32-resbits2;
	sendword2=t1 << resbits2;
    }
    /* write out last word */
    if (resbits2<32) outbuf2[index2++]=sendword2;
    head2.length = thisepoch_converted_entries; /* update header */

   /* eventually open stream 2 */
    switch (type2mode) {
	case 2: /* file in directory */
	    strncpy(ffnam, fname2, FNAMELENGTH);
	    atohex(&ffnam[strlen(ffnam)],head2.epoc);
	    /* printf("filename: %s\n",ffnam); */
	    handle2=open(ffnam,O_WRONLY | O_TRUNC | O_CREAT,FILE_PERMISSONS);
	    if(-1==handle2) {
		fprintf(stderr,"errno: %d\n",errno);
		return 10;}
	    break;
    }
    /* write header 2 and content */
    retval=write(handle2,&head2,sizeof(struct header_2));
    if (retval!=sizeof(struct header_2)) return 20;  /* cannot write header */
    i=index2*sizeof(unsigned int);
    retval=write(handle2,outbuf2,i);
    if (retval!=i) return 21; /* cannot write content */

    /* eventually close stream 2 */
    switch (type2mode) {
	case 2:
	    close(handle2);
	    break;
    }

    /* flush stream 3, write the length and close it */
    if (resbits3<32) outbuf3[index3++]=sendword3;
    head3.length = thisepoch_converted_entries; 

     /* eventually open stream 3 */
    switch (type3mode) {
	case 2: /* file in directory */
	    strncpy(ffnam, fname3, FNAMELENGTH);
	    atohex(&ffnam[strlen(ffnam)],head3.epoc);
	    /* printf("filename: %s\n",ffnam); */
	    handle3=open(ffnam,O_WRONLY | O_CREAT | O_TRUNC,FILE_PERMISSONS);
	    if(-1==handle3) return 11;
	    break;
      }

    /* write header 3 */
    retval= write(handle3,&head3,sizeof(struct header_3));
    /* printf("writing header3, want to send :%d, sent: %d\n", 
       sizeof(struct header_3),retval); */
    if (retval!=sizeof(struct header_3)) return 22; /* write header error */
    i=index3*sizeof(unsigned int);
    retval=write(handle3,outbuf3,i);
    if (retval!=i) return 23; /* write error buffer */

    /* eventually close stream 3 */
    switch (type3mode) {
	case 2:
	    close(handle3);
    }
    /* logging */
    if (verbosity_level>=0) {
	switch (verbosity_level) {
	    case 0: /* bare hex names */
		fprintf(loghandle,"%08x\n",head2.epoc);
		break;
	    case 1: /* log length w/o text and epoch */
		fprintf(loghandle,"%08x\t%d\n",
			head2.epoc,thisepoch_converted_entries);
		break;
	    case 2: /* log length w text and epoch */
		fprintf(loghandle,"epoch: %08x\t entries: %d\n",
			head2.epoc,thisepoch_converted_entries);
		break;
	    case 3: /* log length w text and epoch and setbits */
		fprintf(loghandle,"epoch: %08x, entries: %d, type2bits: %d\n",
			head2.epoc, thisepoch_converted_entries,
			type2bitwidth);
		break;
	    case 4: /* complex log */
		switch (numberofdetectors) {
		    case 4:
			for (i=0;i<5;i++) {
			    sum[i]=0;
			    for (j=0;j<16;j++) 
				if (sumindex[i] & j) sum[i]+=detcnts[j];
			}
			fprintf(loghandle,"%08x\t%d\t%d\t%d\t%d\t%d\n",
				head2.epoc,sum[0],sum[1],sum[2],sum[3],sum[4]);
			break;
		    case 6: /* cater for six-detector case. The single
			       count rates only reflect correctly identified
			       single-detector events */
			for (i=0;i<7;i++) {
			    sum[i]=0;
			    for (j=0;j<16;j++) 
				if ((i==0) || (sumindex[i] == j))
				    sum[i]+=detcnts[j];
			}
			fprintf(loghandle,"%08x\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
				head2.epoc,sum[0],sum[1],sum[2],sum[3],
				sum[4],sum[5],sum[6]);
		}
		break;
	}
	if (flushmode) fflush(loghandle);
	if (debuglog) {
	  fprintf(debuglog,"debuglog:%8x\n",head2.epoc);
	  fflush(debuglog);
	}
    }
 
    /* servo loop for optimal compression parameter */
    /* printf("point 3c, converted: %d\n", thisepoch_converted_entries); */
    if (thisepoch_converted_entries) {
	average_distance = 
	    ((unsigned long long)(1)<<32) / thisepoch_converted_entries;
	if (average_distance<512) average_distance=512;
	/* printf("average_dist: %d\n",average_distance); */
	optimal_width= (int) ((log((float)average_distance)/log(2.)+2.2117)*16.);
	/* do integer version of (log(agv)/log(2)+2.2117)*16 */
	/*tmp=average_distance;optimal_width=0;
    while (tmp>31) {tmp /=2; optimal_width++;};
    optimal_width = optimal_width*16+log_correcttable[tmp&0xf];*/
	/* printf("point 3a\n"); */
	if (filterconst) {
	type2bitwidth_long +=
	    (optimal_width*16-type2bitwidth_long)/filterconst;
	type2bitwidth=type2bitwidth_long>>8;
	};
	tdiff_bitmask = (1<<type2bitwidth)-1; /* for packing */
	/* printf("point3b\n"); */
    }
    return 0;
}
/* prepare first epoch inormation; should lead to a stale file in the past;
   the argument is the delay from the current time in seconds */
unsigned int makefirstepoch(int delay) {
    unsigned long long aep;
    aep=((time(NULL)-delay)*1953125)>>20; /* time in epocs */
    return (unsigned int) (aep & 0xffffffff);
}

int main (int argc, char *argv[]) {
    char infilename[FNAMELENGTH]=""; /* default is stdin */
    int *type2patterntable, *type3patterntable; /* for protocol */
    struct rawevent *inbuffer;
    struct rawevent *inpointer ;  /* input buffer */
    char *ibf2,*ibf2a;   /* char pointer to input buffer */
    int inbytesread, inelements; 
    int statemask = DEFAULT_STATEMASK; /* for result filtering */
    unsigned int cv,dv,t_epoc,t_fine,t_state; /* intermed results */
    unsigned int oldepoc,tfine_old;  /* storage for old epoch */
    int epochinit;
    int retval;  /* general return value */
    unsigned int t1,t2;  /* intermediate variables for bit packing */
    unsigned int tdiff; /* time difference for encoding */
    int i,i1,opt; /* various process variables */
    int exceptcount= 0;
    fd_set rq;  /* for polling */
    struct timeval timeout = {0,500000}; /* timeout for input */
    int fishyness = 0;  /* how many outlying events are acceptable */
    int ignorecount = DEFAULT_IGNORECOUNT; /* how many to ignore initially */
    unsigned long long maxdiff = DEFAULT_MAXDIFF; /* max evt time difference */
    unsigned long long t_new, t_old; /* for consistecy checks */


    /* parsing options */
    opterr=0; /* be quiet when there are no options */
    while ((opt=getopt(argc, argv, "V:i:O:D:o:d:ULl:e:p:q:Q:Fy:m:46")) != EOF) {
	switch (opt) {
	    case 'V': /* set verbosity level */
		if (1!=sscanf(optarg,"%d",&verbosity_level)) return -emsg(1);
		/* printf("verb level: %d\n",verbosity_level); */
		break;
	    case 'i': /* infile name */
		if (1!=sscanf(optarg,FNAMFORMAT,infilename)) return -emsg(2);
		infilename[FNAMELENGTH-1]=0; /* security termination */
		break;
	    case 'O': case 'D': /* outfile2 name and type */
		if (1!=sscanf(optarg,FNAMFORMAT,fname2)) return -emsg(3);
		fname2[FNAMELENGTH-1]=0;  /* security termination */
		if (type2mode) return -emsg(4); /* already defined mode */
		if (opt=='O') type2mode=1; else type2mode=2;
		break;
	    case 'o': case 'd': /* outfile3 name and type */
		if (1!=sscanf(optarg,FNAMFORMAT,fname3)) return -emsg(5);
		fname3[FNAMELENGTH-1]=0;  /* security termination */
		if (type3mode) return -emsg(6); /* already defined mode */
		if (opt=='o') type3mode=1; else type3mode=2;
		break;
	    case 'U': /* universal time epoch mode */
		uepoch=1;
		break;
	    case 'L': /* local epoch mode */
		uepoch=0;
		break;
	    case 'l': /* logfile name */
		if (sscanf(optarg,FNAMFORMAT,logfname) != 1) return -emsg(7);
		logfname[FNAMELENGTH-1]=0;  /* security termination */
		break;
	    case 'e': /* debug file name */
 		if (sscanf(optarg,FNAMFORMAT,debugfname) != 1) return -emsg(36);
		debugfname[FNAMELENGTH-1]=0;  /* security termination */
		break;               
	    case 'p': /* set protocol type */
		if (1!=sscanf(optarg,"%d",&proto_index)) return -emsg(25);
		if ((proto_index<0)| (proto_index>PROTOCOL_MAXINDEX)) 
		    return -emsg(26);
		break;
	    case 'q': /* set timetag bitlength */
		if (1!=sscanf(optarg,"%d",&type2bitwidth)) return -emsg(28);
		if ((type2bitwidth<4) || (type2bitwidth>32)) return -emsg(29);
		break;
	    case 'Q': /* choose filter factor */
		if (1!=sscanf(optarg,"%d",&filterconst)) return -emsg(30);
		if (filterconst<0) return -emsg(31);
		break;
	    case 'F': /* flushmode */
		flushmode=1;
		break;
	    case 'y': /* set initial events to ignore */
		if (1!=sscanf(optarg,"%d",&ignorecount)) return -emsg(33);
		if (ignorecount<0) return -emsg(34);
		break;
	    case 'm': /* max time difference */
		if (1!=sscanf(optarg,"%lld",&maxdiff)) return -emsg(35);
		/* adjust from microseconds to 1/8 nsec */
		maxdiff *= 8000;
		break;
 	    case '4': numberofdetectors=4;break;
 	    case '6': numberofdetectors=6;break;
	}
    }
    /* parameter consistency check */
    if (!type2mode) return -emsg(8); /* are output channels defined? */
    if (!type3mode) return -emsg(9);
    type2bitwidth_long=type2bitwidth<<8; /* for adaptive filtering */
    tdiff_bitmask = (1<<type2bitwidth)-1; /* for packing */
    bitstosend2=type2bitwidth+type2datawidth; /* has to be <32 !! */
 

    /* fill protcol bit tables  */
    type2datawidth= proto_table[proto_index].bitsperentry2;
    type3datawidth= proto_table[proto_index].bitsperentry3;
    type2patterntable= (int*)malloc(sizeof(int)* 
				    proto_table[proto_index].detectorentries);
    type3patterntable= (int*)malloc(sizeof(int)*
				    proto_table[proto_index].detectorentries);
    statemask = proto_table[proto_index].detectorentries-1; /* bitmask */
    if (!type2patterntable | !type3patterntable) return -emsg(27);
    /* fill pattern tables */
    for (i=0;i<proto_table[proto_index].detectorentries;i++) {
	type2patterntable[i]=proto_table[proto_index].pattern2[i];
	type3patterntable[i]=proto_table[proto_index].pattern3[i];
    };
    /* set number of detectors in case we are not in service mode */
    if (proto_index) 
	numberofdetectors = proto_table[proto_index].numberofdetectors;

    /* open log files */
    if (verbosity_level>=0) {
	if (logfname[0]) { /* check if filename is defined */
	    loghandle=fopen(logfname,"a");
	    if (!loghandle) return -emsg(32);
	} else { loghandle = stdout;}
    }
    
    if (debugfname[0]) { /* we got a file name */
      debuglog=fopen(debugfname,"a+");
      if (!debuglog) return -emsg(37);
    } else {
      debuglog=NULL; /* we don't log debug messages */
    }

    /* open I/O streams if possible */
    switch (type2mode) {
	case 0: /* are output channels defined? */
	    return -emsg(8);
	case 1: /* single file */
	    handle2=open(fname2,O_WRONLY|O_CREAT|O_TRUNC,FILE_PERMISSONS);
	    if (-1==handle2) return -emsg(10);
	    break;
    };
    switch (type3mode) {
	case 0: /* are output channels defined? */
	    return -emsg(9);
	case 1: /* single file */
	    handle3=open(fname3,O_WRONLY|O_CREAT|O_TRUNC,FILE_PERMISSONS);
	    if (-1==handle3) return -emsg(11);
	    break;
    };
    if (!infilename[0]) { /* check if a name was assigned */
	handle1=0; /* use stdin as default input */
    } else {
	handle1=open(infilename,O_RDONLY|O_NONBLOCK); /* input stream */
	if (-1==handle1) return -emsg(12);
    }

    /* initiate input buffer */
    inbuffer=(struct rawevent *)malloc(INBUFENTRIES*sizeof(struct rawevent));
    ibf2=(char *)inbuffer; 
    if (!inbuffer) return -emsg(13); /* cannot get inbuffer */

    /* initiate output buffers */
    outbuf2=(unsigned int*)malloc(TYPE2_BUFFERSIZE*sizeof(unsigned int));
    if (!outbuf2) return -emsg(18);
    outbuf3=(unsigned int*)malloc(TYPE3_BUFFERSIZE*sizeof(unsigned int));
    if (!outbuf3) return -emsg(19);
    /* prepare first epoch information */
    t_epoc=makefirstepoch(DEFAULT_FIRSTEPOCHDELAY);
    thisepoch_converted_entries=0;
    for (i=15;i;i--) detcnts[i]=0; /* clear histoogram */
    oldepoc=t_epoc; open_epoch(t_epoc);
    epochinit=0; /* mark first epoch... */
    tfine_old=0;
    /* prepare input buffer settings for first read */
    inbytesread=0; inelements=0; inpointer = inbuffer;
    fishyness=0; t_old = 0;

    while (1) {	/* filling of input buffer */
	/* rescue leftovers from previous read */
	i1 =  inbytesread/sizeof(struct rawevent);
	i1 *= sizeof(struct rawevent);
	for (i=0;i<inbytesread-i1;i++) ibf2[i]=ibf2[i+i1];
	i1=inbytesread-i1;  /* leftover from last time */
	ibf2a=&ibf2[i1]; /* pointer to next free character */
	/* read in next bufferfill */
	/* printf("point1\n"); */
	/* wait for data on handle 1 */
	FD_ZERO(&rq);FD_SET(handle1,&rq);
	timeout.tv_usec=RETRYREADWAIT;timeout.tv_sec=0;
	retval=select(handle1+1,&rq,NULL,NULL,&timeout);
	if (retval==-1) {fprintf(stderr,"error on select: %d",errno);break;}
	if (!FD_ISSET(handle1,&rq)) {continue;}

	inbytesread = read(handle1,ibf2a, 
			   INBUFENTRIES*sizeof(struct rawevent)-i1);
	/*  printf("inbread: %d\n",inbytesread); */
	/* i f (!inbytesread) break;  end of file reached */
	if (!inbytesread) continue; /* wait for next event */
	if (inbytesread==-1)  {
	    fprintf(stderr,"errno: %d ",errno);
	    return -emsg(15); /* other error  */
	}
	
	inbytesread+=i1; /* add leftovers from last time */
	inelements=inbytesread/sizeof(struct rawevent);
	inpointer=inbuffer;
	
	if (ignorecount) { /* dirty trick to eat awayu the first few events */
	    ignorecount--;
	    inpointer++;
	    continue;
	}
	/* main digesting loop */
	do {
	    /* printf("inelements: %d\n",inelements); */
	    /* read one value out of buffer */
	    cv=inpointer->cv; dv=inpointer->dv;
	    t_epoc = cv>>15; /* take most sig 17 bit of timer */
	    t_state = dv & statemask; /* get detector pattern */
	    t_fine = (cv <<17) | (dv >> 15); /* fine time unit */
	    
	    /* trap weired time differences */
	    t_new = (((unsigned long long)t_epoc)<<32)
		     + t_fine; /* get event time */
	    if (t_new < t_old ) { /* negative time difference */
		if ((t_new-t_old) & 0x1000000000000ll) { /* check rollover */
		    inpointer++;
		    continue; /* ...are ignored */
		}
		if (debuglog) {
		  fprintf(debuglog,
			  "chopper: got neg difference; old: %llx, new: %llx\n",
			  t_old,t_new);
		  fflush(debuglog);
		}
	    }
	    if (maxdiff) { /* test for too large timings */
		if (t_new > t_old + maxdiff) {
		    if ((t_old-t_new+maxdiff)&0x1000000000000ll) { /*rollover*/
			if (t_old) { /* make sure to allow time diff at start */
			  inpointer++;
			  if (debuglog) {
			    fprintf(debuglog,
				    "chopper: point 2, old: %llx, new: %llx\n",
				    t_old,t_new);
			    fflush(debuglog);
			  }
			  continue;
			}
			if (debuglog) {
			  fprintf(debuglog,
				  "chopper: got pos difference; old: %llx, new: %llx\n",
				  t_old,t_new);
			  fflush(debuglog);
			}
		    }
		}
	    }
	    t_old = t_new;

	    if (t_epoc!=oldepoc) { /* epoch is changing */
		/* THIS TEST SHOULD BE OBSOLETE... */
		if (((t_epoc-oldepoc) & 0x10000) && epochinit) {/*  rollover */
		    /* something's fishy. ignore value */
		    if (debuglog) {
		      fprintf(debuglog,
			      "chopper: point 3, old: %llx, new: %llx\n",
			      t_old,t_new);
		      fflush(debuglog);
		    }
		    inpointer++;
		    fishyness++;
		    if (fishyness>MAXIMAL_FISHYNESS) {
			fprintf(stderr,"(1)new:%08x, old: %08x; ",
				    t_epoc,oldepoc);return -emsg(16);}
		    continue;
		}
		if ((t_epoc>oldepoc+1)&&(epochinit)) {
		    /* something's fishy - epoch too far */
		    inpointer++;
		    fishyness++;
		    if (fishyness>MAXIMAL_FISHYNESS)  {
			fprintf(stderr,"(2)new:%08x, old: %08x; ",
				t_epoc,oldepoc); return -emsg(16);}
		    continue;
		}
		fishyness=0; /* got something fitting */
		epochinit=1;
		if ((retval=close_epoch())) return -emsg(retval);
		if (open_epoch(t_epoc)) return -emsg(17);
		resbits2=32;sendword2=0;  /* bit packer stream 2 */
		resbits3=32;sendword3=0;  /* bit packer stream 3 */
		thisepoch_converted_entries=0;
		for (i=15;i;i--) detcnts[i]=0; /* clear histoogram */
		exceptcount=0;
		tfine_old=0;
		oldepoc=t_epoc; /* checker for new epoch */
	    }

	    /* type-2 file filling */
	    if (t_fine<=tfine_old ) { /* something's fishy. ignore element */
		 inpointer++;
		 continue;
	    }
	    tdiff=t_fine-tfine_old; /* time difference */
	    tfine_old=t_fine;
	    
	    if (tdiff<2) { /* fudge unlikely events by 0.25 nsec */
		t_fine+=2; tdiff+=2;
	    }	
	    /* printf("tfine:%x, tdiff: %x\n",t_fine,tdiff); */
	    if (tdiff!=(t2=(tdiff & tdiff_bitmask))) { /* long diff exception */
		exceptcount++;
		/* first batch is codeword zero plus a few bits from tdiff */
		t1=tdiff >> type2bitwidth;
		/* save first part of this longers structure */
		if (resbits2==32) {
		    outbuf2[index2++]=t1;
		} else {
		    sendword2 |= (t1 >> (32-resbits2));
		    outbuf2[index2++]=sendword2;
		    sendword2=t1 << resbits2;
		}
	    } 
	    /* short word or rest of data */ 
	    /* add state to shortword */
	    t1 = (t2<<type2datawidth) | type2patterntable[t_state];
	    bitstosend2=type2bitwidth+type2datawidth; /* has to be <32 !! */
	    /* save timing and transmit bits */
	    if (resbits2>=bitstosend2) {
		sendword2 |= (t1 << (resbits2-bitstosend2));
		resbits2 = resbits2-bitstosend2;
		if (resbits2==0) { 
		    outbuf2[index2++]=sendword2;
		    sendword2=0;resbits2=32;
		}
	    } else {
		resbits2=bitstosend2-resbits2;
		sendword2 |= (t1 >> resbits2);
		outbuf2[index2++]=sendword2;
		resbits2=32-resbits2;
		sendword2=t1 << resbits2;
	    }
	    
	    /* type-3 stream filling */
	    t1=type3patterntable[t_state]; /* whatever should be kept... */
	    if (resbits3>=type3datawidth) {
		sendword3 |= (t1 << (resbits3-type3datawidth));
		resbits3 = resbits3-type3datawidth;
		if (resbits3==0) { 
		    outbuf3[index3++]=sendword3;
		    sendword3=0;resbits3=32;
		}
	    } else {
		resbits3=type3datawidth-resbits3;
		sendword3 |= (t1 >> resbits3);
		outbuf3[index3++]=sendword3;
		resbits3=32-resbits3;
		sendword3=t1 << resbits3;
	    }
	    
	    /* histogramming */
	    detcnts[t_state]++;

	    /* switch to next entry in input buffer and possibly reload it */
	    inpointer++;
	    thisepoch_converted_entries++;
	} while (--inelements);
    }
    
    if (verbosity_level>=0) fclose(loghandle);
    /* free buffers */
    free(inbuffer); free(outbuf2);free(outbuf3);
    if (debuglog) fclose(debuglog);
    return 0; /* end begnignly */
}
