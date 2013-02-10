/* chopper2.c : Part of the quantum key distribution software for partitioning
                timestamp data on the high count rate sidde. Description
                see below. Version as of 20090729

 Copyright (C) 2005-2009 Christian Kurtsiefer, National University
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

/* program to partition the output of the timestamp card on the comparator
   side. Consumes the timestamp signal, and generates type-1 packets out of
   it, either in a single file/pipe, or a directory. A logfile for process
   control can be generated. Filespecs for input and type-1 stream can be
   found in the filespec whitepaper.

   status: worked on feb7 2006 with >53k epochs
    added -V 3 option for counting singles 21feb06chk not tested yet
    fixed neg epoch overflow check 7.5.06chk
    merged in changes for deviceindependent protocol 29.7.2009chk.



   usage: chopper2 [-i infilename]
                   -O outfilename1 | -D outfiledir1 | -S socket1
		   [-l logfile ] [-V verbosity] [ -F ]
		   [-U | -L]
		   [-m maxtime ]
		   [-4 | -6] 
		   
   implemented options:
   
 DATA STREAM OPTIONS:
   -i infilename:   filename of source events. Can be a file or a socket
                    and has to supply binary data according to the raw data
		    spec from thetimestamp unit.
   -O fname1:       Outfile name for type 1 raw sifting time files.
                    This option saves all type 1 packets into a the file/FIFO
		    named fname1
   -D dir1:         All type-1 packets are saved into the directory dir1, with
                    the file name being the epoch (filling zero expanded)
		    in hex. Filename is not padded at end.
 ENCODING OPTIONS:
   -U:      universal epoch; the epoch is not only derived from the timestamp
            unit digits, but normalized to unix time origin. This needs the
	    timestamp unit to emit event data with an absolute time tag. 
	    For this to work, the received data cannot be older than xxx hours,
	    or an unnoted ambiguity error will occur.
   -L:      local timestamps only. The epoch is calculated from the
            unmodified timestamp info as received from the unit. This is the
	    default.

 LOGGING & NOTIFICATION
   -l logfile:   Each emitted epoch packet index is logged into this file. The
                 verbosity level controls the granularity of details logged.
		 if nothing is specified, STDOUT is used for logging.
   -V level:     Verbosity level control. level is integer, and by default set
                 to 0. The logging verbosity criteria are:
		 level<0 : no logging
		 0 : log only epoc number (in hex)
		 1 : log epoch, length without text
		 2 : log epoch, length with text
		 3 : log epoch and detailled event numbers for single
		     event counting. format: epoch and 5 cnts spc separated
   -F :          flushmode. If set, the logging output gets flushed after
                 every write attempt.
   -4:           full backwards compatibility option with logging where
                 single counts include local coincidences. Also reduces the
		 number of events in the output log to five (total cnts and
		 individual detector lines).
   -d debugname  specifies the file name of an optional debugging log file.
                 If this file is not provided, no debugging log file is
		 generated. The old debug filename was hardcoded as 
		 /tmp/cryptostuff/choplog2 and has now been removed. Check
		 downstream processing if needed.

PROTECTION OPTION
   -m maxnum:    maximum time for a consecutive event to be meaningful. If
                 the time difference to a previous event exceeds this time,
		 the event is discarded assuming it has to be an error in the
		 timing information. Default set to 0, which corresponds to
		 this option being switched off. Time units is in microseconds.

History:
started coding 21.8.05 chk
compiles 22.8.05 chk
file type 1 seems ok for directory option
works together with pfind and costream  28.8.05chk
inserted flush option 19.9.05chk
inserted -m option (around jan 2006 chk)
inserted -V 3 option
checked rollover problem in neg difference test 070306chk
merges with 6-detector version and introduced -4 compat option 29.7.09chk
made debuglog file optional 10.2.13chk

ToDo:
check buffer sizes
cleanup typedefs
cleanup debuglogs
remove fishyness correction; obsolete with USB hardware??
   
*/
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

/* default definitions etc. */
#define DEFAULT_VERBOSITY 0
#define FNAMELENGTH 200  /* length of file name buffers */
#define FNAMFORMAT "%200s"   /* for sscanf of filenames */
#define DEFAULT_UEPOCH 0   /* choose no universal epoch option */
#define INBUFENTRIES 1024 /* max. elements in input buffer */
#define TYPE1_BUFFERSIZE 3200000  /* should be sufficient for 700kcps events */
#define DEFAULT_FIRSTEPOCHDELAY 60 /* first epoch delay in seconds */
#define FILE_PERMISSONS 0644  /* for all output files */
#define RETRYREADWAIT 500000 /* sleep time in usec after an empty read */
#define DEFAULT_FLUSHMODE 0 /* do not flush by default */
#define MAXIMAL_FISHYNESS 5 /* how many out-ot-time events to detect */
#define DEFAULT_MAXDIFF 0 /* maximum allowable time between events */


/* global variables */
int verbosity_level = DEFAULT_VERBOSITY; /* determie log file format */
char fname1[FNAMELENGTH]="";  /* input file name */
char logfname[FNAMELENGTH]="";   /* log file name */
char debugfname[FNAMELENGTH]=""; /* for debugging info */
int type1mode = 0; /* no mode defined. other tpyes:
		      1: single file, 2: directory save, ... */
int uepoch= DEFAULT_UEPOCH; /* universal epoch mode 0: no, 1: yes */
int handlein, handle1; /* in and out file handles */
FILE* loghandle; /* for log file */
int thisepoch_converted_entries; /* for output buffer */
int detcnts[16]; /* buffer for histogramming events */
int sum[7]; /* do summation */
int index1; /* index in outbuffer field */
unsigned int *outbuf1; /* output buffer pointer */
int flushmode = DEFAULT_FLUSHMODE;
FILE *debuglog;

int smidx[7] = {15,1,2,4,8,3,6}; /* output pattern - now six det capable */
int fourdetectorlogoption = 0; /* this is to force full backward compatibility,
				  where the reported single detector events
			          include possible coincidences. Also, only 
			          four values are logged instead of six. */

/* error handling */

char *errormessage[] = {
    "No error.",   /* 0 */
    "Error reading in verbosity argument.", /* 1 */
    "Error reading in infile name.",
    "Error reading file/directory name for type-2 packets.",
    "duplicate definition of type-1 file.",
    "Error reading logfile name.",  /* 5 */
    "Cannot malloc input buffer.",
    "cannot malloc stream 1 buffer.",
    "Error opening input stream source",
    "cannot open logfile.",
    "no type-1 stream channel defined", /* 10 */
    "Error opening type-1 packet destination",
    "unspecified Input read error",
    "error preparing type-1 steam for new epoch.",
    "cannot write type-1 header", 
    "cannot write type-1 data", /* 15 */
    "too large jump in incoming events for too long",
    "error reading max time difference value (must be >=0)",
    "cannot read debugfile name",
    "cannot open debug file",

};

int emsg(int code) {
  fprintf(stderr,"%s\n",errormessage[code]);
  return code;
};

typedef struct rawevent {unsigned int cv; /* most significan word */
    unsigned int dv; /* least sig word */} re;

typedef struct header_1 { /* header for type-1 stream */
    int tag;
    unsigned int epoc;
    unsigned int length;
    int bitsperentry;
    int basebits;
} h1;
#define TYPE_1_TAG 1
#define TYPE_1_TAG_U 0x101
#define TYPE_2_TAG 2
#define TYPE_2_TAG_U 0x102
#define TYPE_3_TAG 3
#define TYPE_3_TAG_U 0x103
#define TYPE_4_TAG 4
#define TYPE_4_TAG_U 0x104

struct header_1 head1; /* keeps header for type-1 files */

/* lookup table for correction */
#define PL2 0x20000  /* + step fudge correction for epoc index mismatch */
#define MI2 0xfffe0000 /* -2 step fudge correction */
unsigned int overlay_correction[16]= {0,0,0,PL2,  0,0,0,0,
				      MI2,0,0,0,  MI2,MI2,0,0};
/* opening routine to target files & epoch construction */
int open_epoch(unsigned int te) {
    unsigned long long aep,tim;
    unsigned int aepoc=0,finalepoc;
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
    /* printf("finalepoch: %08x, aepo: %08x\n",finalepoc,aepoc);  */
    /* populate headers preliminary */
    head1.tag = uepoch?TYPE_1_TAG_U:TYPE_1_TAG; head1.length = 0;
    head1.epoc = finalepoc; head1.bitsperentry = 49;
    head1.basebits = 4;  /* according to whitepaper */

    /* initialize output buffers and temp storage*/
    index1=0;
    return 0;
};

/* helper for name. adds a slash, hex file name and a termial 0 */
char hexdigits[]="0123456789abcdef";
void atohex(char* target,unsigned int v) {
    int i;
    target[0]='/';
    for (i=1;i<9;i++) target[i]=hexdigits[(v>>(32-i*4)) & 15];
    target[9]=0;
}

int close_epoch() {
    char ffnam[FNAMELENGTH+10];
    int i,j,retval;

    if (!thisepoch_converted_entries) return 0; /* no data collected */

    /* finish stream-1 entries with terminal word */
    outbuf1[index1++]=0; outbuf1[index1++]=0;

    head1.length = thisepoch_converted_entries; /* update header */

   /* eventually open stream 1 */
    switch (type1mode) {
	case 2: /* file in directory */
	    strncpy(ffnam, fname1, FNAMELENGTH);
	    atohex(&ffnam[strlen(ffnam)],head1.epoc);
	    /* printf("filename: %s\n",ffnam); */
	    handle1=open(ffnam,O_WRONLY | O_TRUNC | O_CREAT,FILE_PERMISSONS);
	    if(-1==handle1) {
		/* printf("errno: %d\n",errno); */
		return 11;}
	    break;
    }
    /* write header 1 and content */
    retval=write(handle1,&head1,sizeof(struct header_1));
    if (retval!=sizeof(struct header_1)) return 14;  /* cannot write header */
    i=index1*sizeof(unsigned int);
    retval=write(handle1,outbuf1,i);
    if (retval!=i) return 15; /* cannot write content */

    /* eventually close stream 1 */
    switch (type1mode) {
	case 2:
	    close(handle1);
	    break;
    }
    /* logging */
    if (verbosity_level>=0) {
	switch (verbosity_level) {
	    case 0: /* bare hex names */
		fprintf(loghandle,"%08x\n",head1.epoc);
		break;
	    case 1: /* log length w/o text and epoch */
		fprintf(loghandle,"%08x\t%d\n",
			head1.epoc,thisepoch_converted_entries);
		break;
	    case 2: /* log length w text and epoch */
		fprintf(loghandle,"epoch: %08x \t entries: %d\n",
			head1.epoc,thisepoch_converted_entries);
		break;
	    case 3: /* do complex log */
		if (fourdetectorlogoption) { /* old style logging */
		    for (i=0;i<5;i++) {
			sum[i]=0; 
			/* construct individual detector sums */
			for (j=0;j<16;j++) 
			    if (j & smidx[i]) 
				sum[i]+=detcnts[j];
		    }
		    fprintf(loghandle,"%08x\t%d\t%d\t%d\t%d\t%d\n",head1.epoc,
			    sum[0],sum[1],sum[2],sum[3],sum[4]);
		} else {
		    for (i=0;i<7;i++) {
			sum[i]=0; 
			/* construct individual detector sums */
			for (j=0;j<16;j++) 
			    if ((i<1) || (j == smidx[i])) 
				sum[i]+=detcnts[j];
		    }
		    fprintf(loghandle,"%08x\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
			    head1.epoc,
			    sum[0],sum[1],sum[2],sum[3],sum[4],sum[5],sum[6]);
		}
		break;
	    default:
		fprintf(loghandle,"Undefined verbosity level %d\n",
			verbosity_level);
		break;
	}
	if (flushmode) fflush(loghandle);
    }
    if (debuglog) {
      fprintf(debuglog,"ch2depoch: %08x\n",head1.epoc);
      fflush(debuglog);
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
    struct rawevent *inbuffer; /* holds input values */
    struct rawevent *inpointer ;  /* input buffer */
    char *ibf2,*ibf2a;   /* char pointer to input buffer */
    unsigned int cv,dv,t_epoc; /* intermed results */
    unsigned int oldepoc;  /* storage for old epoch */
    int inbytesread, inelements; 
    int i,i1,retval,opt; /* temp variables */
    int fishyness = 0;  /* how many outlying events are acceptable */
    unsigned long long maxdiff = DEFAULT_MAXDIFF; /* max evt time difference */
    unsigned long long t_new, t_old, t_fine; /* for consistecy checks */


    /* parse options */
    opterr=0; /* be quiet when there are no options */
    while ((opt=getopt(argc, argv, "i:O:D:l:V:ULFm:4d:")) != EOF) {
	switch(opt) {
	    case 'V': /* set verbosity level */
		if (1!=sscanf(optarg,"%d",&verbosity_level)) return -emsg(1);
		/* printf("verb level: %d\n",verbosity_level); */
		break;
	    case 'i': /* read input file name */
		if (1!=sscanf(optarg,FNAMFORMAT,infilename)) return -emsg(2);
		infilename[FNAMELENGTH-1]=0; /* security termination */
		break;
	    case 'O': case 'D': /* outfile1 name and type */
		if (1!=sscanf(optarg,FNAMFORMAT,fname1)) return -emsg(3);
		fname1[FNAMELENGTH-1]=0;  /* security termination */
		if (type1mode) return -emsg(4); /* already defined mode */
		if (opt=='O') type1mode=1; else type1mode=2;
		break;
	    case 'U': /* universal time epoch mode */
		uepoch=1;
		break;
	    case 'L': /* local epoch mode */
		uepoch=0;
		break;
	    case 'l': /* logfile name */
		if (sscanf(optarg,FNAMFORMAT,logfname) != 1) return -emsg(5);
		logfname[FNAMELENGTH-1]=0;  /* security termination */
		break;
	    case 'F': /* enable flushing */
		flushmode =1;
		break;
	    case 'm': /* max time difference */
		if (1!=sscanf(optarg,"%lld",&maxdiff)) return -emsg(17);
		/* adjust from microseconds to 1/8 nsec */
		maxdiff *= 8000;
		break;
	    case '4': /* full backwards compat option */
		fourdetectorlogoption=1;
		break;
	    case 'd': /* a debug log file name is provided */
		if (sscanf(optarg,FNAMFORMAT,debugfname) != 1) return -emsg(18);
		debugfname[FNAMELENGTH-1]=0;  /* security termination */
		break;
	        
	}
    }
    
    if (debugfname[0]) { /* we have a debug file to fill */
      debuglog=fopen(debugfname,"a+");
      if (!debuglog) return -emsg(19);
    } else {
      debuglog=NULL; /* no debug file present */
    }
   
    if (debuglog) fprintf(debuglog,"starting chopper2\n");

    /* prepare input buffer */
    inbuffer=(struct rawevent *)malloc(INBUFENTRIES*sizeof(struct rawevent));
    ibf2=(char *)inbuffer; 
    if (!inbuffer) return -emsg(6); /* cannot get inbuffer */
    /* initiate output buffer */
    outbuf1=(unsigned int*)malloc(TYPE1_BUFFERSIZE*sizeof(struct rawevent));
    if (!outbuf1) return -emsg(7);

    /* open input file */
    if (!infilename[0]) { /* check if a name was assigned */
	handlein=0; /* use stdin as default input */
    } else {
	handlein=open(infilename,O_RDONLY); /* input stream */
	if (-1==handlein) return -emsg(8);
    }

    /* prepare first epoch information */
    /*if (uepoch) {
	t_epoc=makefirstepoch(DEFAULT_FIRSTEPOCHDELAY);
	} else { */
    t_epoc=0;

    thisepoch_converted_entries=0;
    oldepoc=t_epoc; open_epoch(t_epoc);
    t_old=0;
    /* clean histogram */
    for (i=0;i<16;i++) detcnts[i]=0;

    /* prepare input buffer settings for first read */
    inbytesread=0; inelements=0; inpointer = inbuffer;

    /* open log files */
    if (verbosity_level>=0) {
	if (logfname[0]) { /* name defined */
	    loghandle=fopen(logfname,"a");
	    if (!loghandle) return -emsg(9);
	} else {loghandle=stdout;}
    }

    /* open output file if necessary */
    switch (type1mode) {
	case 0: /* are output channels defined? */
	    return -emsg(10);
	case 1: /* single file */
	    handle1=open(fname1,O_WRONLY|O_CREAT|O_TRUNC,FILE_PERMISSONS);
	    if (-1==handle1) return -emsg(11);
	    break;
    };

    /* main conversion loop */
    fishyness=0;
    while (1) {	/* filling of input buffer */
	/* rescue leftovers from previous read */
	i1 =  inbytesread/sizeof(struct rawevent);
	i1 *= sizeof(struct rawevent);
	for (i=0;i<inbytesread-i1;i++) ibf2[i]=ibf2[i+i1];
	i1=inbytesread-i1;  /* leftover from last time */
	ibf2a=&ibf2[i1]; /* pointer to next free character */
	// if (i1) fprintf(stderr,"got leftover: i1= %d bytes /n",i1);
	if (debuglog) 
	  if (i1) fprintf(debuglog,"got leftover: i1= %d bytes /n",i1);

	/* read in next bufferfill */
	inbytesread = read(handlein,ibf2a, 
			   INBUFENTRIES*sizeof(struct rawevent)-i1);
	if (!inbytesread) break; /* end of file reached */
	if (!(inbytesread+1)) { /* error detected */
	    if (errno!=EAGAIN) return -emsg(12); /* other error  */
	    usleep(RETRYREADWAIT);
	    }

	inbytesread+=i1; /* add leftovers from last time */
	inelements=inbytesread/sizeof(struct rawevent);
	inpointer=inbuffer;

	/* main digesting loop */
   	do {
	    /* read one value out of buffer */
	    cv=inpointer->cv; dv=inpointer->dv;
	    t_epoc = cv>>15; /* take most sig 17 bit of timer */
	    t_fine = (cv <<17)| (dv >>15);
	    t_new = (((unsigned long long)t_epoc)<<32)
		+ t_fine; /* get event time */
	    if (t_new<t_old) { /* do general comparison for neg differences */
		if ((t_new -t_old )&0x1000000000000ll) { /* treat rollover */
		    inpointer++;
		    fprintf(stderr,
			    "got negative difference: new: %0llx old: %0llx\n",
			    t_new,t_old);
		    if (debuglog) 
		      { fprintf(debuglog,
				"got negative difference: new: %0llx old: %0llx\n",
				t_new,t_old);
		      }
		    
		    continue; /* ...are ignored */
		}
	    }
	    if (maxdiff) { /* test for too large timings */
		if ( t_new> t_old + maxdiff ) { /* most cases */
		    if ((t_old -t_new + maxdiff) & 0x1000000000000ll) { /* rollover */
			if (t_old) { /* make sure to allow time diff at start */
			    fprintf(stderr,
				    "got pos difference: new: %016llx old: %016llx\n",
				t_new,t_old);
			    if (debuglog) {
			      fprintf(debuglog,
				      "got pos difference: new: %016llx old: %016llx\n",
				      t_new,t_old);
			    }
			    
			inpointer++;
			continue;
			}
		    }
		}
	    }
	    t_old = t_new;

	    if (t_epoc-oldepoc) { /* epoch is changing */
		/*  printf("tepoc: %x, oldepc: %x\n",t_epoc,oldepoc); */
/* SHOULD BE OBSOLETE???.... */
		if (((t_epoc-oldepoc) & 0x10000) && (oldepoc!=0)) {
		    /* something's fishy. ignore value */
		    inpointer++;
		    fishyness++;
		    fprintf(stderr,"got neg tepoc: old: %08x new: %08x",oldepoc,t_epoc);
		    if (debuglog) fprintf(debuglog,"got neg tepoc: old: %08x new: %08x",oldepoc,t_epoc);
		    if (fishyness>MAXIMAL_FISHYNESS) {
			fprintf(stderr,"(negdt): tepoch: %08x, old: %08x\n",
				t_epoc,oldepoc);
			return -emsg(16);
		    }
		    continue;
		}
		if ((t_epoc>oldepoc+1)&&(oldepoc!=0)) {
		    /* something's fishy - epoch too far */
		    inpointer++;
		    fishyness++;
		    fprintf(stderr,"got pos tepoc: old: %08x new: %08x",oldepoc,t_epoc);
		    if (debuglog) fprintf(debuglog,"got pos tepoc: old: %08x new: %08x",oldepoc,t_epoc);

		    if (fishyness>MAXIMAL_FISHYNESS) {
			fprintf(stderr,"(posdt): tepoch: %08x, old: %08x\n",
				t_epoc,oldepoc);
			return -emsg(16);
		    }
		    continue;
		}
		fishyness=0; /* got something fitting */
		if ((retval=close_epoch())) return -emsg(retval);
		if (open_epoch(t_epoc)) return -emsg(13);
		thisepoch_converted_entries=0;
		/* clean histogram */
		for (i=0;i<16;i++) detcnts[i]=0;
		oldepoc=t_epoc; /* checker for new epoch */
	    }
	    thisepoch_converted_entries++;

 	    /* type-1 file filling */
	    outbuf1[index1++]=cv; outbuf1[index1++]=dv;
	    detcnts[dv & 0xf]++; /* histogramming */
	    inpointer++;
	} while (--inelements);
    }

    /* close things benignly */
    if (verbosity_level>=0) fclose(loghandle);

    /* free buffers */
    free(inbuffer); free(outbuf1);
    return 0;    
}
