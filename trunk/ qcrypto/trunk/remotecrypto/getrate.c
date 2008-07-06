/* getrate.c :  Part of the quantum key distribution software to detremine the
                count rate of individual detectors from the output of the
		timestamp data emitted by readevenrs.c. Description
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
   program to determine the count rate of the timestamp card by
   digesting data from the timestamp cards.

   usage:  getrate [-i unfile] [-t time] [-o oufile]

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

  History: 
  started to work sometime.
  added -s and -n option and modified code to work for this 120206chk
  tried to make -n option fast to cope w high count rates 220206chk
  tested up to 350k events / epoch

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
};
int emsg(int code) {
    fprintf(stderr,"%s\n",errormessage[code]);
    return code;
};

typedef struct rawevent {unsigned int cv; /* most significan word */
    unsigned int dv; /* least sig word */} re;

/* counting mask for different output options */
unsigned int cmask[5]={0xf,1,2,4,8}; /* entry 0 for all dets, rest specific */

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
    int splitoption = DEFAULT_SPLITOPTION; /* 0: only sum, !=0: details */
    int j,cnt[5]; /* index through counts and counter itself */
    int numret;  /* number of returned events */
    unsigned int dv=0; /* temporary buffer for dv */
    int i; /* event counter */
    char *ibfraw; /* raw input buffer */
    unsigned int repairidx; /* contains bytes to skip not next read */
    unsigned int retval;
    int firstshot;
    
    /* parse arguments */
    opterr=0; /* be quiet when there are no options */
    while ((opt=getopt(argc, argv, "i:o:t:n:s")) != EOF) {
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
	    case 's': /* multi output option */
		splitoption=1;
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
    do { /* repeat through all rounds.... */
	/* install signal handler for timeout and set timeout */
	timeout1=(timespan+DEFAULT_OVERTIME)/8000; /* in microseconds */
	tv.tv_sec = timeout1/1000000;
	tv.tv_usec = (timeout1-1000000*tv.tv_sec);
	firstshot=0; 
	/* initial reading */
	for (j=0;j<5;j++) cnt[j]=0; /* zero counts */
	inh=fileno(inhandle);
	FD_ZERO(&fd);FD_SET(inh,&fd);
	select(fileno(inhandle)+1,&fd,NULL,NULL,&tv);
	if (FD_ISSET(inh,&fd)) {
	    do { /* read loop */
		retval=read(inh,ibfraw,sizeof(struct rawevent) * 
			    BUF_IN_INENVENTS); /* read raw events */
		if (retval<(sizeof(struct rawevent)+repairidx))
		    return -emsg(6);
		/* cast to event raster */
		inbuf = (struct rawevent *)(&ibfraw[repairidx]);
		numret = (retval-repairidx)/sizeof(struct rawevent); 
		/* repair possible buffer read mismatch */
		repairidx = (repairidx + retval) % sizeof(struct rawevent); 
		/* take care of first shot */
		if (!firstshot) {
		    firstshot=1;
		    re=inbuf[0];inbuf=&inbuf[1];numret--;
		    t0=((unsigned long long)re.cv<<17) +
			((unsigned long long )re.dv >>15)
			+timespan;
		    t1=t0-1;
		}
                /* do parsing */
		for (i=0;i<numret;i++) {
		    /* increment according to mask */
		    dv=inbuf[i].dv;
		    for (j=0;j<5;j++) if (cmask[j] & dv) cnt[j]++;
		    t1=((unsigned long long)inbuf[i].cv<<17) +
			((unsigned long long )dv >>15);
		    if (t1>t0) break;
		}
		if (t1>t0) break;

		usleep(SLEEPTIME);
		/* next read attempt */
		FD_ZERO(&fd);FD_SET(inh,&fd);
		select(fileno(inhandle)+1,&fd,NULL,NULL,&tv);
		if (!FD_ISSET(inh,&fd)) {
		    emergencybreak=1;
		}
	    } while (!emergencybreak);      
	} else {
	    fclose(inhandle);
	}
	/* print result */
	if (splitoption) {
	    fprintf(outhandle,"%d %d %d %d %d\n",
		    cnt[0],cnt[1],cnt[2],cnt[3],cnt[4]);
	} else {
	    fprintf(outhandle,"%d\n",cnt[0]);
	}
	fflush(outhandle);
	
    } while ((--numofrounds)!=0);
    
    free(inbuf);
    fclose(outhandle);
    fclose(inhandle);
    return 0;
}
