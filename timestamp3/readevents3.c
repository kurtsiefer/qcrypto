/* readevents3.c: Part of the quantum key distribution software. This is the
                  user space program to read the timing information from the
		  timestamp unit and generate a clean stream of 64 bit wide
		  time stamps.
		  Version as of 20080225, works also for Ekert-91
		  type protocols.

 Copyright (C) 2005-2008, 2019 Christian Kurtsiefer, National University
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

------

   program to read in events from the timestamp card and do the first
   processing to the data. Configuration happens by commandline options.

   version for usb card....first attempt 17.12.06chk
   status: version as of 18.7.19 chk

   output is directed to stdout in a configurable form, and data acquisition
   is controlled via some signals.

   usage:  readevents [-t treshold | -T tresh_absolute] [-q maxevents]
                      [-r | -R ] [-a outmode] [other options, see below]

   command line options:
   -t treshold       :set input treshold to a given value in DAC units,
                      ranging from 0 to 4095. Defaults to 2905.
   -T tresh_absolute :set input treshold to an absolute value, given in
                      millivolts
   -q maxevents :     quit after a number of maxevents detected events.
                      Default is 0, indicating eternal operation.
   -r :               starts immediate acquisition after card setup.
                      This is default.
   -R :               Initializes card, but does not start acquisition
                      until  a SIGUSR1 is received.
   -a outmode :       Defines output mode. Defaults currently to 0. Currently
                      implemented output modes are:
		      0: raw event code patterns are delivered as 64 bit
		         hexadecimal patterns (i.e., 16 characters)
		         separated by newlines. Exact structure of
			 such an event: see card description.
		      1: event patterns with a consolidated timing
		         (i.e., corrected for spurious samplings from the
			 nudaq card)
		         are given out as 64 bit entities. Format:
			 most significant 49 bits contain timing info
			 in multiples of 0.125 nsec, least significant
			 4 bits contain the detector pattern.

		      2: output consolidated timing info as 64 bit patterns
		         as in option 1, but as hext text.
		      3: output only the phase pattern (for tests only) as
		         decimal values from 0-511 from consolidated timing
			 info.
	              4: output as three space-separated hex patterns for
			 msl, lsl, and pattern
	              5: output as three space-separated decimal patterns for
			 msl, lsl, and pattern

   -v verbosity :     selects how much noise is generated on nonstandard
                      events. All comments go to stderr. A value of 0
		      means no comments. Default is 0.
   -s skew :          set timing skew DAC to value skew (must be
                      between 0 and 4095); default: 2000 (old: 1535)
   -j cal :           run in calibrate mode and use calibration value cal.
   -A :		      Output in absolute time. The timestamp mark is added to
                      the unix time evaluated upon starting of the timestamp
		      card; the resulting time is truncated to the least
		      significant 49 bit in multiples of time units (1/8 nsec).
   -F :               flush after each output line. useful for debugging.
   -p phasepatt :     select phase correction table. currently implemented:
                      -1:  no phase correction
		      0:  phase table for board revision 0
		      2: phase table calibrated for g2 measurement (default)
   -e :               choose external clock (assume 10 MHz)
   -i :               use internal 10 MHz clock. This is the default.
   -x :               exclude spurious outputs (larger than 8 average
                      differences )
   -S skipnum :       skip a given number of events at the beginning (to
                      avoid stale entries in the dma pipeline ?). Default is 0.
   -m opt:            marking option. if set to 1, the unused bits are used to
                      indicate time slips between timestamp time and CPU time.
		      For opt = 0, the phase info is given in bits 4..12
		      (default). for opt=2, all bits are zero.
   -d s1,s2,s3,s4:    add skew times to individual detectors. The supplied
                      values must be comma-separated and identify corrections
 		      in multiples of 125 ps for each detector. This skew
 		      is added to the timing information in case only a single
 		      detector fires. Values can be positive or negative.
 		      This option is only executed if the -A option is active
 		      in order to minimize processing in the central timing
 		      routine.
   -D s1,s2,s3,s4,s5,s6,s7,s8 : Same as the -d option, but this time for
                      taking care of up to 8 detectors. Detector assignment:
                      line 1:    det 1
		      line 2:    det 2
		      line 3:    det 3
		      line 4:    det 4
		      line 1-2:  det 5
		      line 2-3:  det 6
		      line 3-4:  det 7
		      line 4-1:  det 8
   -u                 usb flush mode is on. If no events were detected
                      during one periode, the flush option is activated

   -U devicename:     allows to draw the raw data from the named device node.
                      If not specified, the default is /dev/ioboards/timestamp0
   -Y y1,y2,y3,y4:    ignores detector events if they fall within a certain time
                      of the last event seen by a particular detector. The dead times
		      y1...y4 are measured in multiples of 125ps.

   Signals:
   SIGUSR1:   enable data acquisition. This causes the inhibit flag
              to be cleared, and data flow to start or to be resumed.
   SIGUSR2:   stop data acquisition. leads to a setting of the inhibit flag.
              Data in the FIFO and the DMA buffer will still be processed.
   SIGTERM:   terminates the acquisition process in a graceful way (disabling
              DMA, and inhibiting data acquisition into the hardware FIFO.
   SIGPIPE:   terminates the accquisition gracefully without further
              messages on stderr.

   source structure:
   many card-specific routines are collected in timetag_io.c to keep this
   main code less polluted. declarations in  timetag_io.h


   history of this program:
   - first interface spec 02.08.03 Christian Kurtsiefer
   - all exept the -f option works properly 09.08.03 chk
   - fast/slow counter passover error fixed 11.08.03 chk
   - first try phase interpolation 14.08.03 chk
   - removed -f option. optimized (?) binary output 16.8.03 chk
   - inserted calibration options -j, -c, -s, -p   11.09.03 chk
   - inmode repaired
   - insert -A option 14.07.05 dg
   - added -i, -e options for clock reference
   - added reaction to SIGPIPE 13.9.05chk
   - skipping option aded and repaired 23.11.05
   - re-inserted pipelinebug cure 14.12.05chk
   - added option -m to keep phase information in word / timeslip
   - added phase pattern of card for timestamp 31.12.05chk
   - added skewtime option -d 04.12.05chk
   - fixed cpu time control to system getdate 6.2.06 chk
   - fixed dma access errors at weired transfer addresses 7.2.06 chk
   - made phasepattern 2 default 7.2.06 chk
   - added more detaille error msgs on dmaerror 4.3.06chk
   - fixed control time monitoring???? 12.3.06chk
   - usb version, based on readevents. First version 17.12.06chk
   - converted to USB completely, needs testing 26.12.06chk
   - confirmed working at rates up to 40 kevents/Sec in usb1.
   - confirmed working at rates around 2.3 Mevents/sec. occasionaly
   - complains about congestion....
   - confirmed working at <4Mevents/sec on true fast USB port
   - fixed missing bits and wrong int/ext selection chk240307
   - some cleanup, propagated indexin into out options 3,4,5  25.2.08chk
   - cleanup of usb flush option call
   - added forced dead times for detectors with -Y option 15.7.19chk
   - hopefully fixed dead time correction 18.7.19chk


   ToDo:
   - more cleanup of preprocessing routine for more efficient CPU usage
   - use long long types (violating ANSI C ......?)
   - empty various buffers & FIFOS after disable or before enable
   - use cleaner identifier int/longint for variables relying on 32/64bit
   - check output modes 3,4,5

*/


#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "timetag_io2.h"
#include "usbtimetagio.h"


/* default settings */
#define DEFAULT_VERBOSITY 0
#define MAX_VERBOSITY 1
#define DEFAULT_INPUT_TRESHOLD 3586 /* corresponding to approx -500mV, was 2950*/
#define MAX_INP_TRESHOLD 4095
#define DEFAULT_POLLING_INTERVAL 40 /* in milliseconds */
#define DEFAULT_OUTMODE 0
#define DEFAUT_VERBOSITY 0
#define DEFAULT_MAXEVENTS 0
#define DEFAULT_BEGINFLAG 0 /* for -r/-R option */
#define DEFAULT_SKEW 2000  /* for  -s option */
#define DEFAULT_CLOCKSOURCE 0 /* 0: internal, 1: external */
#define MAX_SKEW_VALUE 4095
#define DEFAULT_CAL 10  /* for -c option */
#define MAX_CAL_VALUE 4095
#define DEFAULT_COINC 10  /* for -c option */
#define MAX_COINC_VALUE 4095
#define DEFAULT_PHASEPATT 2  /* for -p option */
#define MAX_PHASEPATT 2
#define DEFAULT_FLUSHMODE 0 /* flush option switched off by default */
#define DEFAULT_TRAPMODE 0 /* no trapping of spurious events */
#define DEFAULT_SKIPNUM 0 /* forget no entries at beginning */
#define DEFAULT_MARKOPT 0 /* marking option to phasepattern */
//#define DEFAULT_SKEWCORRECT 0 /* no skew correction, 1: 4 detectors,
//				 2: 8 detectors */

/* some global variables */
int outmode = DEFAULT_OUTMODE;
int verbosity = DEFAULT_VERBOSITY;
int currentevents = 0;
int maxevents = DEFAULT_MAXEVENTS;
int beginmode = DEFAULT_BEGINFLAG;
int calmode = 0;
int timemode = 0;
int flushmode = DEFAULT_FLUSHMODE;
int markoption = DEFAULT_MARKOPT;

/* global variables for trapping spurious events & skipping initial entries */
int trap_uval, trap_diff;
int trap_old = 0;
int trap_diffavg = 0; /* status variables filter */
int trap_n = 0; /* counts  events for loading filter mechanism */
int trapmode = DEFAULT_TRAPMODE;

int skipnumber = DEFAULT_SKIPNUM; /* entries at beginning to be skiped */

/* things needed for the USB device  */
#define default_usbtimetag_devicename "/dev/ioboards/timestamp0"
char usbtimetag_devicename[200] = default_usbtimetag_devicename;

/* translation to USB uoperation: more compact patterns */

/* internal constants  */
/* 2**23 bytes can keep 1M events - this is 400 msec at a rate of
   2.5 Mevents per sec */
#define size_dma  (1<<23) /* kernel buffer size, should be multiple of 4k */
#define dmasize_in_longints (size_dma / sizeof(int))
#define dmabuf_complainwatermark (dmasize_in_longints * 4 / 5)

/*    FIXME!!!!! how does this work in usb mode? */
/* byte counting issue. For long latency times (assume 1 second) and a max
   event rate of 2^21 per sec, we have 2^24 bytes transferred. Assuming we
   want to detect unattended irqs for 2^4 secs, we need to be able to count
   2^28 bytes. Byte count, however, should stay below 2^30 to avoid integer
   sign issues. We choose 2^29 bytes as rollover, or 2^26 quads. */
#define QUADMASK 0x3ffffff /* mask for 26 bits */
/* this is to detect overflow */
#define QUADMASK2 (QUADMASK & ~(dmasize_in_longints - 1))
/* this is to mask out the rollover of the DMA buffer */
#define QUADMASK3 (dmasize_in_longints -1)

/*---------------------------------------------------------------*/
/* initiate_phasetable */
typedef struct otto {int pattern; int value;} otto;
struct otto nopattern[] =
{{ -1, -1}};
struct otto defaultpattern[] =
{	{6, 4}, {7, 5}, {12, 3}, {14, 7}, {39, 4}, {136, 5}, {140, 7},
	{142, 5}, {152, 8}, {156, 11}, {216, 9}, {295, 2}, {359, 1},
	{371, 15}, /* the nasty one */
	{375, 1}, {472, 10}, {497, 14}, {499, 14}, {504, 12}, {505, 13}, {507, 11},
	{ -1, -1}
};
struct otto pattern_rev_1 [] = /* new card, tested with skew=2000 */
{ {6, 6}, {7, 5}, {14, 6}, {39, 4}, {140, 5}, {152, 7}, {156, 5}, {216, 7}, {295, 1},
	{359, 0}, {371, 0}, {375, 3}, {472, 8}, {497, 15}, {499, 15}, {504, 11}, {505, 13},
	{507, 14}, { -1, -1}
};
struct otto pattern_rev_2[] = /* for g2 meas at TMK's setup (3rd SG card) */
{ {6, 5}, {7, 4}, {12, 6}, {14, 5}, {39, 3}, {136, 6}, {140, 6},
	{142, 6}, {152, 7}, {156, 7}, {216, 8}, {295, 2}, {359, 1},
	{371, 14}, {375, 0}, /* the nasty one */
	{472, 9}, {497, 13}, {499, 13}, {504, 11}, {505, 12}, {507, 13},
	{ -1, -1}
};
int phasetable[512];
void initiate_phasetable(struct otto *patterntab) {
	int i;
	for (i = 0; i < 512; i++) phasetable[i] = 0; /* clear useless events */
	for (i = 0; patterntab[i].value >= 0; i++) /* set the few good ones */
		phasetable[patterntab[i].pattern] = patterntab[i].value << 15;
}

/* ----------------------------------------------------------------*/
/* error handling */
char *errormessage[] = {
	"No error.",
	"Wrong verbosity level",
	"Input treshold out of range (0..4095)",
	"Illegal number of max events (must be >=0)",
	"Can't open USB timetag device driver",
	"mmap failed for DMA buffer",  /* 5 */
	"specified outmode out of range",
	"dma buffer overflow during read",
	"reached dma complainwatermark",
	"skew value out of range (0..4095)",
	"calibration value out of range (0..4095)", /* 10 */
	"coincidence value out of range (0..4095)",
	"negative number of elements to skip.",
	"marking option out of range (0, 1 or 2)",
	"wrong skew format. needs -d v1,v2,v3,v4",
	"Cannot parse device name", /* 15 */
	"needs at least 4 dead time entries: -Y d1,d2,d3,d4[,d5[,d6...]]",
};
int emsg(int code) {
	fprintf(stderr, "%s\n", errormessage[code]);
	return code;
};


/* -------- Accquring the local time ------- */
unsigned long long dayoffset_1; /* contains local time in 1/8 nsecs
				   when starting the timestamp card */
unsigned long long dayoffset[16]; /* to hold timings */
unsigned long long lasttime[16]; /* holds last event for a given detector pattern */
unsigned int ddeadpatt[16]; /* dead time correction, indexed by pattern */
char patt2det[16] = { 1, 2, 4, 8, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}; /* translation table patt->det */
int deadtimecorrect = 0;

struct timeval timerequest_pointer; /*  structure to hold time requeste  */

unsigned long long my_time(void)
{	unsigned long long lret; /* fr preparing in local units */

	if (gettimeofday(&timerequest_pointer, NULL)) {
		fprintf(stderr, "gettime err in readevents; errno: %d\n", errno);
		return 0;
	}

	lret = timerequest_pointer.tv_sec;
	lret *= 1000000;
	lret += timerequest_pointer.tv_usec;
	lret = (lret * 8000) << 15;
	return (lret);
}


/* ------------------ signal handlers --------------------------*/

/* structures for timer interrupts */
struct itimerval newtimer = {{0, 0}, {0, DEFAULT_POLLING_INTERVAL * 1000}};
struct itimerval stoptime = {{0, 0}, {0, 0}};
unsigned int controltime_coarse = 0; /* in multiples of (1<<30) nanoseconds */
unsigned int controltime_cv, controltime_dv; /* for getting actual time diff */
unsigned int controltime_getmeone = 1; /* call for a new value */
long long int avg_diff = 0; /* average difference for time tracking */

/* handler for itimer signal SIGALRM. Just restarts the timer.. */
void timer_handler(int sig) {
	static unsigned long long mt, mt2; /* buffer for current time */
	static long long int ct_ref_time, mtd;
	/* float cons = 1E-9/(1<<18); for display of difference */
	if (sig == SIGALRM) {
		setitimer(ITIMER_REAL, &newtimer, NULL); /* restart timer */

		/* new version, tied to system clock */
		mt = my_time();
		if (1) { /* exclude strange time readings */
			mt2 = mt - dayoffset_1; /* corrected by dayoffset */
			ct_ref_time = ((((unsigned long long)controltime_cv << 32) +
			                controltime_dv)) ; /* in 1/8 nsec */
			/* averaged difference between PC clock and timestamp clock */
			mtd = (long long int)(mt2 - ct_ref_time);
			avg_diff += ((long long int)mtd - avg_diff) / 300; /* avg time is 10 sec */

			/* avg_diff=0; */
			controltime_coarse = (mt2 - avg_diff) >> 48; /* in 2^30 nsec */
		}
	}
	controltime_getmeone = 1; /* ask for fresh timing info */
}
int handler_filehandle;
/* handler for SIGUSR1 / SIGUSR2 */
void usersig_handler(int sig) {
	switch (sig) {
	case SIGUSR1: /* start DMA */
		trap_n = 0; trap_old = 0; trap_diffavg = 0;
		set_inhibit_line(handler_filehandle, 0);
		break;
	case SIGUSR2: /* stop DMA */
		set_inhibit_line(handler_filehandle, 1);
		break;
	}
}
/* handler for termination */
int terminateflag;
void termsig_handler(int sig) {
	switch (sig) {
	case SIGTERM: case SIGKILL:
		fprintf(stderr, "got hit by a term signal!\n");
		terminateflag = 1;
		break;
	case SIGPIPE:
		/* stop acquisition */
		fprintf(stderr, "readevents:got sigpipe\n");
		terminateflag = 1;
	}
}


/* ----------------------- processing of raw data --------------- */
/* intermediate buffer for processed data */
struct processedtime {unsigned int cv; unsigned int dv;} processedtime;
struct processedtime outbuf[dmasize_in_longints / 2];
/* function to digest data from the DMA buffer. quadsprocessed and quadsread
   represent indices to 32-bit entities in the DMA buffer. return value
   is the number of processed 32-bit-entries, or <0 if a DMA buffer overflow
   occured.
*/
int process_quads(void *sourcebuffer, int startquad, int endquad) {
	unsigned int *events;
	int startindex, endindex, i;
	int numberofquads;
	int j;  /* processing variables */
	unsigned int ju; /* for parsing binary numbers */
	unsigned int u; /* contains events */
	/* main processing variables */
	int quadsthere;
	unsigned int cv, cvd, v1, dv, fastcnt, b0;
	char *formatstring;
	static char formatstring_1[] = "event: msl: %08x; lsl: %08x\n";
	static char formatstring_2[] = "%08x%08x\n";
	int markit = 0;   /* for debugging time error */
	unsigned long long current_time;
	int pattern; /* holds detector pattern */

	events = (unsigned int *)sourcebuffer;
	numberofquads = (endquad - startquad) & QUADMASK3 ; /* anticipate roll over*/

	/* what if startquad == endquad? */
	if (numberofquads == 0) return 0; /* only look for pos transfers */
	/* complain if buffer is too filled */
	if ( numberofquads > ((int) dmabuf_complainwatermark) ) {
		fprintf(stderr, "numofquads: %d, complainwm: %d\n", numberofquads, ((int) dmabuf_complainwatermark));
		return -1;
	}

	startindex = startquad % dmasize_in_longints;
	endindex   =   endquad % dmasize_in_longints;

	switch (outmode) {
	case 0:   /* just for simple printout */
		for (i = startindex; i != endindex; i = ((i + 1) % dmasize_in_longints)) {
			u = events[i];
			if (verbosity) { /* long version */
				printf("index: %04d, value: %08x :", i, u);
				for (ju = 0x80000000; ju; ju >>= 1) printf("%d", ((ju & u) ? 1 : 0));
				printf("\n");
			} else {
				printf("%08x\n", u); /* only hex code */
			}
		}
		/* check if max event mechanism is active */
		if (maxevents) {
			currentevents++;
			if (currentevents == maxevents) {
				terminateflag = 1;
				return numberofquads;
			}
		}
		return numberofquads;

	/* do first processing  in other cases */
	case 1: case 2:
		i = startindex;
		j = 0; /* start target index */
		for (quadsthere = numberofquads;
		        quadsthere > 1;
		        quadsthere -= 2, i = ((i + 2) % dmasize_in_longints)) {
			/* extract coarse  val and check for consistency */
			cv = events[i + 1];
			dv = events[i];
			/* check for dummies - to be implemented ??*/
			if (!(cv | dv)) { /* both are zero...indicates an error */
				/* Commented out because of noise level
				           fprintf(stderr,"err: double zero\n"); */
				continue;
			}

			cvd = (cv >> 16) - controltime_coarse + 2; /* difference plus 2 */
			/* for debugging stop */
			if (cvd > 4) { /* allow for approx 2 sec difference */
				fprintf(stderr, "timing out of range; cv=%d, control=%d, dv=%d, idx: %d\n", cv, controltime_coarse, events[i], i);
				/* continue; */
				if (markoption == 1) markit += 0x10;
				/* FIXME: for debug: try not to realign 4-byte entities */
				/* quadsthere--;i=((i+1) % dmasize_in_longints); */
				continue;
			}
			/* now we should be consistent. no mixing necessry anymore */
			/* get first and second entry */
			v1 = ((dv & 0xc000) >> 12) | ((dv & 0x30000) >> 16); /* event lines */

			fastcnt = (dv & 0x3e00) << 10;
			if (markoption == 0)
				markit = (dv << 4); /* bring phase pattern in place */
			/* construct lower significant u32, containing c0-c12, c_1..c_4,
			   and the event bits in the least significant nibble.
			   order there: bit 3..0=inA..InD */
			dv = (dv & 0xff000000) | /* bits c5..c12 */
			     fastcnt | /* bits c0..c4 */
			     phasetable[dv & 0x1ff] |  /* do phase interpolation */
			     v1 | /* event lines */
			     (markit & 0x1ff0);  /* for debugging */

			/* repair pipelining bug */
			if ( (fastcnt < 0x00880000)) {
				b0 = dv & 0x80000000; /* remember carry */
				dv += 0x01000000;
				if (b0 && !(dv & 0x80000000)) cv++; /* eventually do carry */
			}

			if (timemode == 1) {
				pattern = dv & 0xf; /* detector pattern */
				current_time = (((unsigned long long)cv) << 32)
				               + (unsigned long long)dv
				               /* correction for time skew of individual detectors */
				               + dayoffset[pattern];
				if (!deadtimecorrect) {
					outbuf[j].cv = (unsigned int) (current_time >> 32);
					outbuf[j].dv = (unsigned int) (current_time & 0xffffffff);
				} else {
					if (current_time - lasttime[pattern] > ddeadpatt[pattern]) {
						lasttime[pattern] = current_time;
						outbuf[j].cv = (unsigned int) (current_time >> 32);
						outbuf[j].dv = (unsigned int) (current_time & 0xffffffff);
					} else {
						lasttime[pattern] = current_time;
						continue; /* next element in for loop */
					}
				}
			} else {
				outbuf[j].cv = cv; outbuf[j].dv = dv;
			}
			/* keep track of movin difference */
			if (controltime_getmeone) {
				controltime_cv = cv; controltime_dv = dv; controltime_getmeone = 0;
			}

			if (trapmode) {
				trap_uval = cv >> 9; /* time in units of 8ms */
				trap_diff = trap_uval - trap_old; trap_old = trap_uval;
				if (trap_n > 1024) {
					/* test if diffference exceeds 8 avg differences */
					if ((trap_diff < 0) || ((trap_diff * 32) > trap_diffavg)) {
						/* we have an exception */
						j--;
						goto dontcount;

					}
				}
				trap_diffavg += trap_diff - trap_diffavg / 256;
dontcount: trap_n++;
			}
			j++;

			/* check if max event mechanism is active */
			if (maxevents) {
				currentevents++;
				if (currentevents == maxevents) {
					terminateflag = 1;
					return numberofquads;
				}
			}
		}

		/* dump event */
		switch (outmode) {
		case 1: /* output as binary values */
			if (skipnumber >= j ) {
				skipnumber -= j;
			} else {
				fwrite(&outbuf[skipnumber], sizeof(struct processedtime),
				       j - skipnumber, stdout);
				skipnumber = 0;
				if (flushmode) fflush(stdout);
			}
			break;
		case 2: /* output as one single / separated hex pattern */
			formatstring = verbosity ? formatstring_1 : formatstring_2;
			if (skipnumber >= j ) {
				skipnumber -= j;
			} else {
				for (i = skipnumber; i < j; i++) {
					fprintf(stdout, formatstring,
					        outbuf[i].cv, outbuf[i].dv);
				}
				if (flushmode) fflush(stdout);
				skipnumber = 0;
			}
			break;
		}
		return numberofquads - quadsthere;
		break;

	case 3: case 4: case 5: /* more text */

		/* updated for cleaner indexing in USB card */
		i = startindex;
		for (quadsthere = numberofquads;
		        quadsthere > 1;
		        quadsthere -= 2, i = ((i + 2) % dmasize_in_longints)) {
			/* extract coarse val and check for consistency */
			cv = events[i + 1]; /* part containing coarse timing */
			dv = events[i]; /* part containing fine time, phase, det pattern */

			cvd = (cv >> 16) - controltime_coarse + 2; /* difference plus 2 secs*/
			if (cvd > 4) { /* allow for approx 2 sec difference */
				fprintf(stderr, "timing out of range; cv=%d, control=%d, dv=%d, idx: %d\n", cv, controltime_coarse, events[i], i);
				if (markoption == 1) markit += 0x10;
			}
			/* get first and second entry */
			v1 = ((dv & 0xc000) >> 12) | ((dv & 0x30000) >> 16); /* event lines */

			fastcnt = (dv & 0x3e00) << 10;
			if (markoption == 0)
				markit = (dv << 4); /* bring phase pattern in place */
			/* construct lower significant u32, containing c0-c12, c_1..c_4,
			   and the event bits in the least significant nibble.
			   order there: bit 3..0=inA..InD */
			dv = (dv & 0xff000000) | /* bits c5..c12 */
			     fastcnt | /* bits c0..c4 */
			     phasetable[dv & 0x1ff] |  /* do phase interpolation */
			     v1 | /* event lines */
			     (markit & 0x1ff0);  /* for debugging */

			/* repair pipelining bug */
			if ( (fastcnt < 0x00880000)) {
				b0 = dv & 0x80000000; /* remember carry */
				dv += 0x01000000;
				if (b0 && !(dv & 0x80000000)) cv++; /* eventually do carry */
			}

			/* dump event */
			switch (outmode) {
			case 3: /* output only phase pattern as decimal number */
				fprintf(stdout, "%d\n", dv & 0x1ff);
				break;
			case 4: /* output as three space-separated hex patterns for
			       msl, lsl, pattern */
				fprintf(stdout, "%08x %08x %04x\n", cv, dv, (dv & 0x1ff));
				break;
			case 5: /* output as three space-separated hex patterns for
			       msl, lsl, pattern */
				fprintf(stdout, "%d %d %d\n", cv, dv, (dv & 0x1ff));
				break;
			}
			/* check if max event mechanism is active */
			if (maxevents) {
				currentevents++;
				if (currentevents == maxevents) {
					terminateflag = 1;
					return numberofquads;
				}
			}
		}
		return numberofquads - quadsthere;
	}
	return -1; /* should never be reached */
}

int main(int argc, char *argv[]) {
	int opt; /* for parsing command line options */
	int verbosity_level = DEFAULT_VERBOSITY;
	int input_treshold = DEFAULT_INPUT_TRESHOLD;
	int fh; /* file handle for device file */
	unsigned char *startad = NULL; /* pointer to DMA buffer */
	/* main loop structure */
	int overflowflag;
	int quadsread, quadsprocessed, oldquads;
	int retval;
	unsigned int bytesread = 0;
	int skew_value = DEFAULT_SKEW;
	int calib_value = DEFAULT_CAL;
	int coinc_value = DEFAULT_COINC;
	int phase_patt = DEFAULT_PHASEPATT;
	int clocksource = DEFAULT_CLOCKSOURCE;
	//int skewcorrectmode = DEFAULT_SKEWCORRECT;
	int dskew[8]; /* for detector skew correction, indexed by detector number */
	unsigned int ddead[8]; /* dead time correction, indexed by detector number */
	int i, j;
	int USBflushmode = 0; /* to toggle the flush mode of the firmware */
	int USBflushoption = 0; /* indicates activated flush option */
	int usberrstat = 0;

	/* set skew to zero by default */
	for (i = 0; i < 8; i++) dskew[i] = 0;



	/* --------parsing arguments ---------------------------------- */

	opterr = 0; /* be quiet when there are no options */
	while ((opt = getopt(argc, argv, "t:q:rRAa:v:s:c:j:p:FiexS:m:d:D:uU:Y:")) != EOF) {
		switch (opt) {
		case 'v': /* set verbosity level */
			sscanf(optarg, "%d", &verbosity_level);
			if ((verbosity_level < 0) || (verbosity_level > MAX_VERBOSITY))
				return -emsg(1);
			break;
		case 't': /*set treshold value */
			sscanf(optarg, "%d", &input_treshold);
			if ((input_treshold < 0) || (input_treshold > MAX_INP_TRESHOLD))
				return -emsg(2);
			break;
		case 'q': /* set max events for stopping */
			sscanf(optarg, "%d", &maxevents);
			if (maxevents < 0) return -emsg(3);
			break;
		case 'a': /* set output mode */
			sscanf(optarg, "%d", &outmode);
			if ((outmode < 0) || (outmode > 5)) return -emsg(6);
			break;
		case 'r':
			beginmode = 0; /* starts immediate data acquisition */
			break;
		case 'R':
			beginmode = 1; /* goes into stoped mode after start */
			break;
		case 's': /* set skew value to other than default */
			sscanf(optarg, "%d", &skew_value);
			if ((skew_value < 0) || (skew_value > MAX_SKEW_VALUE))
				return -emsg(9);
			break;
		case 'j': /* set calib value and swoitch on calib mode  */
			sscanf(optarg, "%d", &calib_value);
			calmode = 1;
			if ((calib_value < 0) || (calib_value > MAX_CAL_VALUE))
				return -emsg(10);
			break;
		case 'c': /* set coincidence value to other than default */
			sscanf(optarg, "%d", &coinc_value);
			if ((coinc_value < 0) || (coinc_value > MAX_COINC_VALUE))
				return -emsg(11);
			break;
		case 'p': /* select phase pattern */
			sscanf(optarg, "%d", &phase_patt);
			if ((phase_patt < -1) || (phase_patt > MAX_PHASEPATT))
				return -emsg(12);
			break;
		case 'A': /* set absolute time */
			timemode = 1;
			break;
		case 'F': /* switch flush on after every output */
			flushmode = 1;
			break;
		case 'i': /* internal clock */
			clocksource = 0;
			break;
		case 'e': /* external clock */
			clocksource = 1;
			break;
		case 'x': /* suppress erratic events */
			trapmode = 1;
			break;
		case 'S': /* skip first few events */
			sscanf(optarg, "%d", &skipnumber);
			if (skipnumber < 0) return -emsg(12);
			break;
		case 'm': /* defines usage of bits 4..14 in outword */
			sscanf(optarg, "%d", &markoption);
			if ((markoption < 0) || (markoption > 2)) return -emsg(13);
			break;
		case 'd': /* read in detector skews */
			if (4 != sscanf(optarg, "%d,%d,%d,%d", &dskew[0], &dskew[1],
			                &dskew[2], &dskew[3])) return -emsg(14);
			break;
		case 'D': /* read in detector skews for 8 detectors */
			i = sscanf(optarg, "%d,%d,%d,%d,%d,%d,%d,%d",
			           &dskew[0], &dskew[1], &dskew[2], &dskew[3],
			           &dskew[4], &dskew[5], &dskew[6], &dskew[7] );
			if (i < 4) return -emsg(14);
			while (i < 8) {
				dskew[i] = 0; i++;
			}
			break;
		case 'u': /* switch on USB flushmode */
			USBflushoption = 1;
			break;
		case 'U': /* specify alternate device name */
			if (1 != sscanf(optarg, "%199s", usbtimetag_devicename))
				return -emsg(15);
			usbtimetag_devicename[199] = 0;
			break;
		case 'Y': /* add artificial dead time to detectors*/
			i = sscanf(optarg, "%u,%u,%u,%u,%u,%u,%u,%u",
			           &ddead[0], &ddead[1], &ddead[2], &ddead[3],
			           &ddead[4], &ddead[5], &ddead[6], &ddead[7] );
			if (i < 4) return -emsg(16);
			while (i < 8) {
				ddead[i] = 0; i++;
			}
			deadtimecorrect = 1;
			break;
		default:
			fprintf(stderr, "usage not correct. see source code.\n");
			return -emsg(0);
		}
	}

	/* initiate phasetable with defaults */
	switch (phase_patt) {
	case 0:
		initiate_phasetable(defaultpattern);
		break;
	case 1:
		initiate_phasetable(pattern_rev_1);
		break;
	case 2:
		initiate_phasetable(pattern_rev_2);
		break;
default: case -1:
		initiate_phasetable(nopattern);
	}


	/* ------------- initialize hardware  ---------------------*/
	/* open device */
	fh = open(usbtimetag_devicename,  O_RDWR);
	if (fh < 0) return -emsg(4);


	/* initialize DMA buffer */
	startad = mmap(NULL, size_dma, PROT_READ | PROT_WRITE, MAP_SHARED, fh, 0);
	if (startad == MAP_FAILED) return -emsg(5);

	/* prepare device */
	Reset_gadget(fh);

	/* fudging: resets this the card? */
	reset_slow_counter(fh); /* make sure to start at t=0 */

	/* do timetag hardware init */
	initialize_DAC(fh);
	initialize_rfsource(fh);
	set_DAC_channel(fh, 0, coinc_value);  /* coincidence delay stage */
	set_DAC_channel(fh, 1, input_treshold); /* input reference */
	set_DAC_channel(fh, 2, calib_value);  /* calibration delay stage */
	set_DAC_channel(fh, 3, skew_value);   /* clock skew voltage */
	/* choose 10 MHz clock source */
	if (clocksource) {
		rfsource_external_reference(fh);
	} else {
		rfsource_internal_reference(fh);
	}

	set_inhibit_line(fh, 1); /* inhibit events for the moment */
	set_calibration_line(fh, calmode ? 0 : 1); /* disable calibration pulse */

	initialize_FIFO(fh); /* do master reset */
	handler_filehandle = fh;  /* tell irq hndler about file handle */

	/* ------------ install IPC and timer signal handlers -----------*/
	signal(SIGTERM, &termsig_handler);
	signal(SIGKILL, &termsig_handler);
	signal(SIGPIPE, &termsig_handler);

	/* external user signals to start/stop DMA */
	signal(SIGUSR1, &usersig_handler);
	signal(SIGUSR2, &usersig_handler);
	/* polling timer */
	signal(SIGALRM, &timer_handler);

	/* ------------- start acquisition - main loop ---------*/

	terminateflag = 0; overflowflag = 0;
	quadsprocessed = 0; currentevents = 0;

	start_dma(fh);

	usleep(50);

	/* for checking timer consistency */
	controltime_coarse = 0; avg_diff = 0;
	controltime_cv = 0; controltime_dv = 0; controltime_getmeone = 0;

	dayoffset_1 = my_time();

	/* translate detector pattern into dead time index, and detector skew into dayoffset */
	for (i = 0; i < 16; i++) {
		j = patt2det[i];
		ddeadpatt[i] = (j < 0) ? 0 : (ddead[j] << 15); /* correct position of time shift */
		dayoffset[i] = dayoffset_1 + ((j < 0) ? 0 : (long long int)dskew[j]);
	}


	setitimer(ITIMER_REAL, &newtimer, NULL);

	if (!beginmode) set_inhibit_line(fh, 0); /* enable events to come in */

	/* reminder: onequad is 4 bytes in usb mode, or 2 quads per event */
	quadsread = 0; oldquads = 0; /* assume no bytes are read so far */

	do {
		pause();
		if (terminateflag) break;

		/* get number of arrived quads; all incremental, can roll over */
		bytesread = ioctl(fh, Get_transferredbytes);
		quadsread = bytesread / 4; /* one quad is a 32 bit entry read
				  in by the USB unit... */

		/* true overflow or irq error in internal linked buffer chain */
		if (((quadsread - oldquads) &  QUADMASK2 ) || (bytesread & 0x80000000)) {
			usberrstat = ioctl(fh, Get_errstat);
			overflowflag = 1; break;
		}

		if (USBflushoption) {
			/* switch on flush mode if there is no data */
			if (oldquads == quadsread) {
				if (!USBflushmode) {
					usb_flushmode(fh, 50); /* 500 msec */
					USBflushmode = 1;
				}
			} else if (USBflushmode) { /* we are in this mode */
				if (quadsread - oldquads > 8) { /* we see stuff coming again */
					usb_flushmode(fh, 0); /* switch off flushmode */
					USBflushmode = 0;
				}
			}
		}

		oldquads = quadsread;
		/* do processing */
		retval = process_quads(startad, quadsprocessed, quadsread);
		if (retval < 0) {
			overflowflag = 2;
		} else {
			quadsprocessed += retval;
		};

	} while ( !terminateflag &&  !overflowflag);


	/* ----- the end ---------- */
	setitimer(ITIMER_REAL, &stoptime, NULL); /* switch off timer */
	set_inhibit_line(fh, 1);
	stop_dma(fh);
	close(fh);

	/* error messages */
	switch (overflowflag) {
	case 1:
		fprintf(stderr,
		        "bytes: %x quadsread: %x, oldquads: %x, procesed: %x\n",
		        bytesread, quadsread, oldquads, quadsprocessed);

		fprintf(stderr, "USB error stat: %d\n", usberrstat);
		return -emsg(7);
	case 2: return -emsg(8);
	}
	return 0;
}
