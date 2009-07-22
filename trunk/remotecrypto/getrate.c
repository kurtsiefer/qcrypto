/* getrate.c :  Part of the quantum key distribution software to detremine the
                count rate of individual detectors from the output of the
		timestamp data emitted by readevenrs.c. Description
                see below. Version as of 20090722

		This program replaces getrate and getrate2 at various locations

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

--
   program to determine the count rate of the timestamp card by
   digesting data from the timestamp cards.

   usage:  getrate [-i unfile] [-t time] [-o oufile] [-t time] [-n events]
                   [-s ] [-6 | 8] [-c]

   options/parameters:

   -i infile:    source of the raw data stream from the timestamp card.
                 If not specified, stdin is chosem

   -o outfile:   target for the count result. if not chosen, stdout is used.

   -t time:      integration time in 1/8 nanoseconds. If nothing is specified,
                 1 epoch length or 2^29 nsec is chosen.

   -n evts:      terminates after evts rounds of counting. if evts=0, it loops
                 forever. default is evts = 1. 

   -s :          split detector results. If this option is set, four colums
                 corresponding to individual detector events are given, plus a
		 fifth one for the overall events (can be lower than sum of 4
		 due to coincidences). Switched off by default.
   -6 :          same as -s option, but with 6 detectors, where the two
                 additional ones are identified by 1-2 and 2-3 coincidences
   -8 :          same as -6 option, but with two more detectors corresponding
                 to coincidences 3-4 and 4-1
   -c :          compensation option. If this is set, the single counts get also
                 incremented if there is a coincidence event, e.g., a 
		 coincidence event between detectors 1 and 2 contributes also to
		 singles 1 and 2 if this option is set; otherwise, it does not
		 contribute to the singles.


  History: 
  started to work sometime.
  added -s and -n option and modified code to work for this 120206chk
  tried to make -n option fast to cope w high count rates 220206chk
  tested up to 350k events / epoch
  modified to cater for more than 4 detectors 160507chk
  changed ambicuous counts for multiple events 280507chk
  modified core structure to avoid hangup in USB continuous mode...
  still needs to be tested for reliability 080707chk
  backported an error in free from getrate2.c 250708chk
  added the zero count option - 16.5.09 chk
  This is a merge between getrate2 and getrate.c - seems to work16.5.09chk
  merged in the coincidence correction option  21.7.09chk
  
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>

#define FNAMELENGTH 200  /* length of file name buffers */
#define FNAMFORMAT "%200s"   /* for sscanf of filenames */
#define DEFAULT_TIMESPAN ((long long int)1<<32)  /* length of one epoch */
#define DEFAULT_OVERTIME ((long long int)8000000*100) /* 100 ms */
#define DEFAULT_EVENTS 1 /* number of events to count */
#define DEFAULT_SPLITOPTION 0 /* no splitopion in output */
#define BUF_IN_INENVENTS (1<<18) /* max number of input events in 50 ms */
#define SLEEPTIME 30000 /* sleep for 30 msec between burst reads */

/* error handling */
char *errormessage[] = {
    "No error.",
    "error parsing input file name",
    "error parsing output file name",
    "error parsing time interval",
    "timespan is not positive",
    "cannot open input file", /* 5 */
    "error reading pattern",
    "error opening output file",
    "error parsing round number",
    "number of rounds negative.",
    "cannot malloc buffer",   /* 10 */
    "error in select command",
    "timeout in select call",
};
int emsg(int code) {
    fprintf(stderr,"%s\n",errormessage[code]);
    return code;
};

typedef struct rawevent {unsigned int cv; /* most significan word */
    unsigned int dv; /* least sig word */} re;

/* counting mask for different output options */
#define DETMASK 0xf /* mask for detectorpattern */
unsigned int cmask[9]={0xf,1,2,4,8,3,6,0xc,9}; /* entry 0 for all dets, rest specific */

int main (int argc, char *argv[]) {
    int opt; /* command parsing */
    char infilename[FNAMELENGTH]="";
    char outfilename[FNAMELENGTH]="";
    long long int timespan=DEFAULT_TIMESPAN;
    FILE *inhandle;
    struct rawevent re; /* for reading in an event */
    struct rawevent *inbuf; /* input buffer */
    int inh;
    unsigned long long t0,t1, timeout1;
    struct timeval tv;
    fd_set fd;  /* for timeout */
    FILE *outhandle;
    int emergencybreak;
    int numofrounds = DEFAULT_EVENTS; /* number of epochs to report */
    int splitoption = DEFAULT_SPLITOPTION; /* 0: only sum, 4: 4 detectors,
					      6 or 8: 6 or 8 detectors */
    int j,cnt[9]; /* index through counts and counter itself */
    int numret=0;  /* number of returned events */
    unsigned int dv=0; /* temporary buffer for dv */
    int i; /* event counter */
    char *ibfraw; /* raw input buffer */
    unsigned int repairidx; /* contains bytes to skip not next read */
    unsigned int retval;
    int firstshot;
    int zerocountoption = 1; /* if set, a zero is printed if there are no cnts,
				if zero, an error takes place */
    int coincidencecorrection=0;

    /* parse arguments */
    opterr=0; /* be quiet when there are no options */
    while ((opt=getopt(argc, argv, "i:o:t:n:s68c")) != EOF) {
	switch (opt) {
	    case 'i': /* set input file name */
		if(1!=sscanf(optarg,FNAMFORMAT,infilename)) return -emsg(1);
		
		break;
	    case 'o': /* set output file name */
		if(1!=sscanf(optarg,FNAMFORMAT,outfilename)) return -emsg(2);
		break;
	    case 't': /* set time */
		if (1!=sscanf(optarg,"%lli",&timespan)) return -emsg(3);
		if (timespan<=0) return -emsg(4);
		break;
	    case 'n': /* number of rounds */
		if (1!=sscanf(optarg,"%d",&numofrounds)) return -emsg(8);
		if (numofrounds<0) return -emsg(9);
		break;
	    case 's': /* multi output option for 4 detectors */
		splitoption=4;
		break;
	    case '6': /* six detectors */
		splitoption=6;
		break;
	    case '8': /* eight detectors */
		splitoption=8;
		break;
	    case 'c': /* coincidence coorrection option */
		coincidencecorrection=1;
		break;
	}
    }
    /* try to open input file */
    if (infilename[0]) {
	inhandle=fopen(infilename,"r");
	if (!inhandle) return -emsg(5);
    } else {inhandle=stdin; };
    
    /* get input buffer */
    ibfraw = (char *)malloc(sizeof(struct rawevent) 
				      * BUF_IN_INENVENTS);
    if (!ibfraw) return -emsg(10);
    
    /* open out file */
    if (outfilename[0]) {
	outhandle=fopen(outfilename,"r");
	if (!outhandle) return -emsg(7);
    } else {outhandle=stdout; };
    
    /* just to keep compiler quiet */
    t0=0;t1=0;inbuf=NULL;

    emergencybreak=0;
    repairidx=0;
    firstshot=0; /* to get very first timing information */
    for (j=0;j<9;j++) cnt[j]=0; /* zero counts */
    do { /* main loop for reading in data */

	/* prepare to read in raw timestamp data */
	timeout1=(timespan+DEFAULT_OVERTIME)/8000; /* in microseconds */
	tv.tv_sec = timeout1/1000000;
	tv.tv_usec = (timeout1-1000000*tv.tv_sec);
	inh=fileno(inhandle);
	FD_ZERO(&fd);FD_SET(inh,&fd);
	retval=select(fileno(inhandle)+1,&fd,NULL,NULL,&tv);
	/* trap any nonsenese coming out of the select call */
	if (retval<1) { /* something silly has happened */
	    if (retval<0) { /* there was an error */
		emergencybreak=-1; /* indicate error condition from select */
		break;
	    }
	    /* now we have to deal with a timeout; how so? */
	    if (!zerocountoption) {
		emergencybreak=2; /* for the moment, just mark the condition */
		break;
	    } else { /* we need to print zero and resume the loop */
		fprintf(outhandle,"%d",cnt[0]); /* total counts */
		/* display whatever detcount was selected */
		for (j=1;j<=splitoption;j++) fprintf(outhandle," %d",cnt[j]);
		fprintf(outhandle,"\n"); /* terminate with newline */
		fflush(outhandle);
		
		/* clear counters and update expiry timer t0 */
		for (j=0;j<9;j++) cnt[j]=0;
		t0 += timespan+DEFAULT_OVERTIME;
		
		/* check for break conditions */
		numofrounds--; /* result 0: terminate, <0: foreverloop */
		if (numofrounds<0) numofrounds = -1; /* avoid overflow */
		if (numofrounds==0) { /* we need to terminate */
		    emergencybreak = 1;
		    break;
		}
		/* try for next read */
		continue;
	    }
	}

	/* filling buffer */
	if (repairidx) {
	    /* transfer residual stuff at end of buffer to beginning */
	    for (i=0;i<repairidx;i++)
		ibfraw[i] = ibfraw[i+numret*sizeof(struct rawevent)];
	}
	/* do real read */
	retval=read(inh,&ibfraw[repairidx], (sizeof(struct rawevent) * 
		    BUF_IN_INENVENTS)-repairidx); /* read raw events */

	if (retval<(sizeof(struct rawevent)-repairidx)) {
	    emergencybreak=-2;
	    break;
	}

	/* cast to event raster */
	inbuf = (struct rawevent *)ibfraw;
	numret = (retval+repairidx)/sizeof(struct rawevent);

	/* repair possible buffer read mismatch for next round */
	repairidx = (repairidx + retval) % sizeof(struct rawevent); 
	
	if (!firstshot) { /* load first timing event */
	    firstshot=1;
	    re=inbuf[0];inbuf=&inbuf[1];numret--;
	    t0=((unsigned long long)re.cv<<17) +
		((unsigned long long )re.dv >>15)
		+timespan;
	    t1=t0-1;
	}
	
	/* do actual counting */
	for (i=0;i<numret;i++) {
	    /* find out if timing is ripe for output*/
	    t1=((unsigned long long)inbuf[i].cv<<17) +
		((unsigned long long )dv >>15);
	    if (t1>t0) { /* do output and update new timer */
		/* print result */
		fprintf(outhandle,"%d",cnt[0]); /* total counts */
		/* display whatever detcount was selected */
		for (j=1;j<=splitoption;j++) fprintf(outhandle," %d",cnt[j]);
		fprintf(outhandle,"\n"); /* terminate with newline */
		fflush(outhandle);
		
		/* clear counters and update expiry timer t0 */
		for (j=0;j<9;j++) cnt[j]=0;
		t0 += timespan;
		
		/* check for break conditions */
		numofrounds--; /* result 0: terminate, <0: foreverloop */
		if (numofrounds<0) numofrounds = -1; /* avoid overflow */
		if (numofrounds==0) { /* we need to terminate */
		    emergencybreak = 1;
		    break;
		}

	    }

	    /* increment according to mask */
	    dv=inbuf[i].dv;
	    if (coincidencecorrection) { /* we should do the correction */
		for (j=1;j<9;j++) 
                    /* no extra cnts taken */
		    if ((dv & cmask[j]) == cmask[j]) cnt[j]++; 
	    } else { /* no correction */
		for (j=1;j<9;j++) 
                    /* no extra cnts taken */
		    if ((dv & DETMASK) == cmask[j]) cnt[j]++; 
	    }


	    if (cmask[0]&dv) cnt[0]++; /* any count */
	}

	usleep(SLEEPTIME); /* should only be reached in case of a successful read */
	
    } while (!emergencybreak);
    
    switch (emergencybreak) {
	case -2: /* error in read call */
	    retval = -emsg(6); 
	    break;
	case -1: /* error condition from select */
	    retval = -emsg(11);
	    break;
	case  1: /* legitimate end of the loop */
	    retval = 0;
	    break;
	case  2: /* timeout condition from select */
	    retval = -emsg(12);
	    break;
    }
    
    free(ibfraw);
    fclose(outhandle);
    fclose(inhandle);
    return retval;
}
