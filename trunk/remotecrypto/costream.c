/* costream.c : Part of the quantum key distribution software for identifying
                temporal coincidences, tracking clock differences and
                initial key sifting on the high count rate side. Description
                see below. Version as of 20070101

 Copyright (C) 2005-2007,2010,2011 Christian Kurtsiefer, National University
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

   program to process type-1 and type-2 streams on side b to recover
   coincidences between different timings. As an output, the program generates
   type-4 streams of acknowlegements to party A, and type-3 streams for local
   raw key storage. File type descriptions can be found in the filespec
   whitepaper. Besides the streams, logging information is given for
   notification of various digesting consumers, and coinidence time tracking
   parameters can be supplied and logged.


   usage:
         costream [-i type-2 streamfile] | [-d type-2 directory]
                  [-I type-1 streamfile] | [-D type-1 directory]
		  [-o type-3 streamfile] | [-f type-3 directory]
                  [-O type-4 streamfile] | [-F type-4 directory]
                  [-b type-3 bellfile]   | [-B type-3 directory]
		  -e startepoch [-q epochnumber]
		  [-k] [-K]
		  -t timediff
		  [-w coincidence window] [-u tracking window]
		  [-Q filterparameter for timedifference]
		  [-r bitnumber] [-R servoconstant]
		  [-p protocolindex]
		  [-l logfile1] [-L logfile2] [-m logfile3] [-M logfile4]
		  [-n logfile5] [-V verbosity]
		  [-T zeroeventpolicy ]
		  [-G flushmode ]
		  [-a accidendist ]
  		  [-H histogramname ]
  		  [-h histogramlength ] 
		  [-S s1,s2,s3,s4 ]
		  
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
   -O fname4:       Outfile name for type 4 compressed sifting index files.
                    This option saves all type 4 packets into a the file/FIFO
		    named fname4
   -F dir4:         All type-4 packets are saved into the directory dir4, with
                    the file name being the epoch (filling zero expanded)
		    in hex. Filename is not padded at end.
   -o fname3:       same as option -O, but for type-3 files
   -f dir3:         same as option -d, but for type-3 files
   -b bellfile:     same as option -O, but for type-3 BELL files
   -B belldir:      same as option -d, but for type-3 BELL directories

   -k :             if set, type-2 streams are removed after consumption
		    if the directory input has been chosen.
   -K :             if set, type-1 streams are removed after consumption
		    if the directory input has been chosen.
  DATA MANAGEMENT OPTIONS:
   -e startepoch    epoch to start with.
   -w window        coincidence time window in 1/8 nsec
   -u window        coincidence time window in for tracking purpose.
   -Q filter        filter constant for tracking coincidences. positive numbers
                    refer to events, negative to time constants in
		    microseconds. A value of zero switches tracking off; this
		    is the default.
   -a accdist       distance between the real coincidence winow and the 
                    window for accidental coincidences in 1/8 nsec. default is
		    160 (corresp. to 20 nsec)
		    
   -p protocolindex defines the working protocol. Currently implemented:
                    0: service mode, emits all bits into stream 3 locally
		    1: standard BB84, emits only result in stream 3
		    (2: rich bb84: emits data and base/error info in stream 3)
		    3: deviceindep protocol with the 6det connected to
		       the chopper side (low cnt rate)
		    4: deviceindep proto with te 4det connected to the
		       chopper side
                    5: BC protocol; similar to standard BB84, but handles basis
		       differently.
   -q epochnum      defines how many epochs should be converted before the
                    program stops. When set to 0, it loops forever; this is
		    the default.
   -r bitnumber     number of bits for coding the difference in stream 4.
                    default is 8.
   -R servoconst    filter time constant for stream 4 bitlength optimizer.
                    The larger the num, the longer the memory of the filter.
		    for num=0, no change will take place. This is also the
		    default.
   -t timediff      time difference between the t1 and t2 input streams. This
                    is a mandatory option, and defines the initial time
		    difference between the two local reference clocks in
		    multiples of 125ps.
   -T zeropolicy    policy how to deal with no valid coincidences in present
                    epoch. implemented:
		    0: do not emit a stream-3 and stream-4 file.
		    1: only emit a stream-4 file, no stream-3 file to notify
		       the other side to discard the corresp. package. This is 
		       the default.
		    2: emit both stream-3 and stream-4 files and leave the
		       cleanup to a later stage
   -H histoname     defines a file containing the histogram of time differences
                    between different detector combinations. If this is empty,
                    no histogram is taken or sent. For a histogram to be
                    prepred the mode of operation must be 0 (service info) to
		    obtain the full 4x4 matrix (or 4x6 for proto3+4).
   -h histolen      number of epochs to be included in a histogram file.
                    default is 10.
   -S s1,s1,s3,s4   detector skew information. This option adds a detector-
                    dependent skew time to single-detection events. This option
		    makes only sense for some nonstandard applications and
		    is similar to the detector skew option in readevent3.c
   
  LOGGING & NOTIFICATION:
   -l logfile1:  notification target for consumed epochs of type-1 packets.
                 logged are epoch numbers in hex form.
   -L logfile2:  notification target for consumed epochs of type-2 packets.
                 logged are epoch numbers in hex form.
   -m logfile3:  notification target for type-3 files packets.
                 logged are epoch numbers in hex form.
   -M logfile4:  notification target for type-4 files packets.
                 logged are epoch numbers in hex form.
   -n logfile5:  notification target for general information. The logging
                 content is defined by the verbosity level. If no file is
		 specified, or - as a filename, STDOUT is chosen.
   -V level:     Verbosity level control. level is integer, and by default set
                 to 0. The logging verbosity criteria are:
		 level<0 : no output
		 0 : output bare hex names of processed data sets
		 1 : output handle and number of key events in this epoch
		 2 : same as option 1 but with text
		 3 : output epoch, processed events, sream-4 events, current
		     bit with for stream 4 compression with text
		 4 : output epoch, processed events, sream-4 events, current
		     bit with for stream 4 compression, servoed time
		     difference,estimated accidental coincidences, and
		     accepted coincidences with text
		 5 : same as verbo 4, but without any text inbetween
   -G mode       flushmode. If 0, no fflush takes place after each processed
                 packet. different levels:
                 0: no flushing
		 1: logfile4 gets flushed
		 2: logfiles for stream3, stream4, standardlog get flushed
		 3: all logs get flushed



  History:
  written specs: 21.8.05 chk
  compiles and seems to run somehow, first testing seems ok;
  output content is not yet verified.   28.8.05chk
  problem w pattern solved 29.8.05chk
  inserted -q option; corrected stream2consistency check  30.8.05chk
  documented verbo options 10.9.05chk
  added flushmodes and waiting option for files 19.9.05chk
  repaired W option to u option for GNU compatib 8.10.05chk
  histogram options added 4.12.05chk
  debug log changed to find death reason. try notify benign end. 7.2.06 chk
 
   modified to get stat right before reading file...compiles feb12_06
   hopefully repaired date overflow bug in bit #63  18.10.06chk
   added detector deskew option -S for special apps 11.5.10chk
   merged in Ekert protocol modifications from separate branch 29.7.11chk


  ToDo:
  check decision matrix  carefully
  document all proto an verbo options
  add more verbo options
 
  think of how to treat empty packets - allowed.
 remove thisepoch_converted_entries or truecoincies

*/

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

/* default definitions */
#define DEFAULT_VERBOSITY 0
#define DEFAULT_COINCWINDOW 8 /* in 1/8 nsec. only half of the true value */
#define DEFAULT_TRACKWINDOW 40 /* in 1/8 nsec. only half of the true value */
#define DEFAULT_FILTER  0  /* for coinc tracker 0 is off  */
#define SERVO_GRAN_SHIFT 12
#define SERVO_GRANULARITY (1<<SERVO_GRAN_SHIFT) /* fixed comma calculation */
#define SERVO_BASETIME 8000 /* base time reference is in microseconds */
#define FNAMELENGTH 188  /* length of file name buffers */
#define FNAMFORMAT "%188s"   /* for sscanf of filenames */
#define DEFAULT_KILLMODE1 0 /* don't delete stream-1 files */
#define DEFAULT_KILLMODE2 0 /* don't delete stream-2 files */
#define DEFAULT_STARTEPOCH 0
#define DEFAULT_EPOCHNUMBER 0 /* How many epochs to consider; 0: eternal */
#define DEFAULT_PROTOCOL 1 /* standard BB84 */
#define DEFAULT_FILTERCONST_4 0  /* no adaptive bitwidth  */
#define DEFAULT_BITDEPTH 17 /* should be optimal for 100 kevents/Sec */
#define DEFAULT_STREAM4BITWIDTH 8 /* for stream 4 */
#define MIN_4_BITWIDTH 3 /* for stream-4 packing */
#define MAX_4_BITWIDTH 20 /* for stream-4 packing */
#define DEFAULT_ZEROPOLICY 1 /* only emit stream-4 packets in no events */
#define MAX_SERVOOFFTIME (100000000*8) /* switch off servo if time >100 msec */
#define DEFAULT_WAITFORFILE 550000 /* usleep after unsuccessful file tsts */
#define DEFAULT_WAITWRITTEN 100000 /* wait 100 ms after file has appeared */
#define MAXFILETESTS 40 /* wait for about 22 seconds for a file to arrive */
#define DEFAULT_FLUSHMODE 0 /* no flush */
#define DEFAULT_ACCDIST 160 /* 20 nsec outsinde coincidence window */
#define DEFAULT_HISTODEPTH 128 /* number of timebins recorded */
#define DEFAULT_HISTOLEN 10 /* number of epochs to be integrated */
#define DEFAULT_READLOOPS 40 /* number of read atempts to get a stream file */
#define DEFAULT_SLEEP_LOOP 50000 /*  usec to sleep between read attempts */

/* binary buffers */
#define RAW1_SIZE 6400000 /* should last for 1400 kcps */
#define RAW2_SIZE 2000000 /* should last for 1400 kcps */ 
#define RAW3_SIZE 150000  /* more than enough? */
#define RAW4_SIZE  40000   /* plenty */


FILE *debuglog;

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

typedef struct protocol_details_B { /* used in costream program */
    int bitsperentry3;   /* what ends up in local sifted key stream */
    int bitsperentry4;   /* any transmitted data on the way back */
    int bitsperentry5;   /* number of bits in the test file */
    int detectorentries; /* number of detectorentries; 16 for 4 detectors;
			    this value -1 is used as bitmask for status */
    int expected2bits;   /* expected bits from the other side. Will cause an
			    error if the streams don't natch this. */
    int decsize ;   /* size of an int array which will contain the decision
		       what to do. The array will be indexed by a value
		       obtained by ORing the local bits in the least
		       significant four bits with whatever was received from
		       the remote stream 2, shifted by four bits to the left.
		       The binary value of its 
		       content is a multi-bitfield structure, where the
		       lsbits are a resulting entry3 pattern, the next bits
		       are the resulting stream-4 pattern, followed by
		       one bit for the decision wether the event should be
		       ignored (0) or not (1), and another decision bit for
		       classifying an event as key (0) or test (1) event. */
    void (*fill_decision)(int*); /* helper function to fill decision table. 
				    the argument is the decision array. */
} pd_B;

#define PROTOCOL_MAXINDEX 5
/* helper functions for filling in the decision table */
void FILL_DEC_PROTO0(int *t) {/* parameter is 8 bits wide , with the stream-2
				bits in bit7..4 of p3, stream-1 bits in lsbits.
				result is 8 bits for stream-3 (a copy of p3),
				and the four bits in stream-1 to stream-4.
				The decision bit (bit 12) is always 1. */
    int p3;
    for (p3=0;p3<256;p3++) { /* all patterns */
	t[p3]=p3 | /* for stream-3 data */
	    ((p3 & 0xf)<<8) |  /* for stream-4 data */
	    0x1000; /* decision bit */
	    }
}
void FILL_DEC_PROTO1(int*t) {/* for standard BB84. parameter is 5 bits wide,
				bits0..3 from stream 1, bit 4 from stream 2.
				Result is
                                one bit wide for stream-3 data (local raw key),
				and 0 bits for stream-4 data (acknowledge).
				The decision bit (bit 1) represents a basis
				match. sequence stream 1: (lsb)V -H + (msb)
			        base bit from stream 2: 1 is +-, 0 is HV */
    int bbtab[32]={0,3,0,0, 2,0,0,0, 0,0,0,0, 0,0,0,0, /* base 0 */
		   0,0,3,0, 0,0,0,0, 2,0,0,0, 0,0,0,0};
    int i;
    for (i=0;i<32;i++) t[i]=bbtab[i];
}
void FILL_DEC_PROTO3(int *t) {/* For dev-indep with 6 detectors on chopper
				 sode. The parameter is 7 bit wide, with the
				 stream-2 bits in bit6..4 of p3,
				 stream-1 bits in lsbits.
				 result is 1 bit for stream-3, 2 bits for
				 stream-5, and 3 bits for stream-4.
				 Ignoreevent and testbit decisions are set
				 accordingly */
    /* The Bell file contains rrll bits, where rr and ll are indices of
       remote and local detectors, ranging from 0 to 3.
       The stream-4 handshake is either 0-3 for the local det index, or 4
       for a key event. The keeping pattern is 0x80, the testpattern 0x100
    */
    int interestingtab[36]= /* table with addr,value for legal entries */
	{0x41,0x040,  0x44,0x041, /* key combination events */
	 0x01,0x100,  0x02,0x111,  0x04,0x122,  0x08,0x133, 
	 0x11,0x104,  0x12,0x115,  0x14,0x126,  0x18,0x137, 
	 0x21,0x108,  0x22,0x119,  0x24,0x12a,  0x28,0x13b, 
	 0x31,0x10c,  0x32,0x11d,  0x34,0x12e,  0x38,0x13f
	};

    int i;
    for (i=0;i<256;i++) t[i]=0; /* default is illegal pattern */
    for (i=0;i<18;i++) t[interestingtab[i*2]]=interestingtab[i*2+1] | 0x80;
}
void FILL_DEC_PROTO4(int*t) {/* For the devindep protocol, with  4 detectors 
				on the chopper side. The parameter is 5 bits
				wide, bits0..4 from stream 1, bit 4 from
				stream 2. Result is one bit for stream-3 key 
				data, 2 bits for incomplete Bell tests,
				and 3 bits for stream-4 data (test/key).
				The stream-4 events are as in proto3, the
				keeping pattern is 0x20, test pattern 0x40. */
    int i;
    for (i=0;i<32;i++) t[i]=0; /* illegal by default */
    for (i=0;i<4;i++) 
	t[0x10+(1<<i)]=0x40 + (i*5) + 0x20; /* test, s-4 and s-5 same */
    t[0x13]=0x10+0x20; t[0x16]=0x11+0x20; /* key bits */
}
void FILL_DEC_PROTO5(int*t) {/* modified BB84. parameter is 4 bits wide,
				bits0..3 from stream 1. Result is
                                two bits for stream-3 data (basis/result),
				and 0 bits for stream-4 data (acknowledge).
				The decision bit (bit 2) is always on for
				single detector events.
				sequence stream 1: (lsb)V -H + (msb)
			        base bit from stream 2: 1 is +-, 0 is HV */
    int bbtab[16]={0,4,6,0, 5,0,0,0, 7,0,0,0, 0,0,0,0};

    int i;
    for (i=0;i<16;i++) t[i]=bbtab[i];
}

struct protocol_details_B proto_table[] = {
    {/* protocol 0: all bits go everywhere */
        8,4,0,16,4, /* 16 entries in the tables p3_1 and p3_2 */
	256, /* size of combined pattern */
	&FILL_DEC_PROTO0,
    },
    { /* protocol 1: standard BB84. assumed sequence:  (LSB) V,-,H,+ (MSB);
	 HV basis: 0, +-basis: 1, result: V-: 0, result: H+: 1 */
        1,0,0,16,1,
	32, /* size of combined pattern */
	&FILL_DEC_PROTO1
    },
    /* protocol 2: rich BB84. assumed sequence:  (LSB) V,-,H,+ (MSB);
	HV basis: 0, +-basis: 1, result: V-: 0, result: H+: 1 
	if an illegal pattern was detected, a pair info pattern (2) or a
	multi/no coincidence pattern (3) is recorded*/
    /* for the moment, this is just a copy of protocol 0 */
    {/* protocol 2: all bits go everywhere */
	8,4,0,16,4, /* 16 entries in the tables p3_1 and p3_2 */
	256, /* size of combined pattern */
	&FILL_DEC_PROTO0,
    },
    {/* protocol 3: deviceindependent - chopper on 6det side.
	chopper transmits 1-out-of-6 info, costream returns
	1-out-of-5 to first side. */
	1,3,4,16,3,/* one keybit, 3 ack bits, 4 bellbits, 16??, 2 t2bits */
	128, /* size of combined pattern */
	&FILL_DEC_PROTO3,
    },
    {/* protocol 4: all bits go everywhere */
	1,3,2,16,1, /* one keybit, 3 ack bits, 2 bellbits, 16??, 1 t2bit */
	32, /* size of combined pattern */
	&FILL_DEC_PROTO4,
    },
    {/* protocol 5: modified BB84. assumed sequence:  (LSB) V,-,H,+ (MSB);
	HV basis: 0, +-basis: 1, result: V-: 0, result: H+: 1 */
        2,0,0,16,0,
	16, /* size of combined pattern */
	&FILL_DEC_PROTO5
    },

    /* helper functions for filling in the decision table */
};

/* ---------------------------------------------------------------------- */


/* histogram stuff. For preparing a histogram of time differences between
   corresponding detector events. An array of 17 (25) entries contains events
   for all valid detector combinations. the 25th entry corresponds to
   detector events which do not correspond to pairs.
   old: 17th column, but that was never used so I changed it to 25
*/

unsigned int histo[25][DEFAULT_HISTODEPTH]; /* array for counting */
int histos_to_go;
int histolen = DEFAULT_HISTOLEN; /* numbers of histograms */
char histologname[FNAMELENGTH]; /* log file name base */
int histidx[256]; /* histogram index */


/* clear histogram */
void clear_histo(void) {
    int i,j;
    for (i=0;i<25;i++) for (j=0;j<DEFAULT_HISTODEPTH;j++) histo[i][j]=0;
    histos_to_go = histolen;
    fprintf(debuglog,"histolen: %d\n",histolen);
}

/* initialize histogram index and clear field */
void init_histo(void){
    int i,x,y;
    for (i=0;i<256;i++) histidx[i]=24; /* most of them are illegal */
    for (i=0;i<16;i++) histidx[(16<<((i>>2)&3))|(1<<(i&3))]=i; /* legal 4x4 */
    /* for calibration: mix 2x4 detectors from all combinations. This is not
       entirely correct, but adds some wrong events onto the legal ones, but
       should be good enough for calibration.... */
    for (i=16;i<24;i++){
	x=(i&4)>>2;y=i&3;
	histidx[(0x30<<x)+(0x01<<y)]=i; /* remote has 6 detectors */
	histidx[(0x03<<x)+(0x10<<y)]=i; /* local has 6 detectors */
    }
    clear_histo();
}


/* helper for name. adds a slash, hex file name and a termial 0 */
char hexdigits[]="0123456789abcdef";
void atohex(char* target,unsigned int v) {
    int i;
    target[0]='/';
    for (i=1;i<9;i++) target[i]=hexdigits[(v>>(32-i*4)) & 15];
    target[9]=0;
}

/* print out histogram; returns error code if any */
int emit_histo(unsigned int epoch) {
    char hl2[FNAMELENGTH+10];
    int i,j;
    FILE *hh; /* histogram handle */
    if (histologname[0]) {
	strncpy(hl2,histologname,FNAMELENGTH);
	j=strlen(hl2);
	for (i=0;i<8;i++) hl2[j+i] = hexdigits[(epoch>>(4*(7-i)))&0xf];
	hl2[j+8]=0; /* string termination */
	if (!(hh=fopen(hl2,"w"))) {
	    return 68; /* cannot open histo file */
	}
 fprintf(hh,"# time difference histogramming output. Start epoch: %08x, contains %d epochs.\n# The timing info in column 1 is in multiples of 125ps. The\n# next 24 columns contain legal events, column 26 the number of illegal events.\n",epoch-histolen,histolen);fflush(hh);
	for (j=0;j<DEFAULT_HISTODEPTH;j++) {
	    fprintf(hh,"%d ",j-DEFAULT_HISTODEPTH/2);
	    for (i=0;i<25;i++) fprintf(hh,"%d%c",histo[i][j],i<24?' ':'\n');
	}
	fclose(hh);
    }
    clear_histo();
    return 0;
}


/* error handling */
char *errormessage[] = {
  "No error.",
  "Error reading in verbosity argument.", /* 1 */
  "Error reading file/directory name for type-1 packets.",
  "Error reading file/directory name for type-2 packets.",
  "Error reading file/directory name for type-3 packets.",
  "Error reading file/directory name for type-4 packets.", /* 5 */
  "duplicate definition of type-1 file.",
  "duplicate definition of type-2 file.",
  "duplicate definition of type-3 file.",
  "duplicate definition of type-4 file.",
  "error parsing startepoch.", /* 10 */
  "error parsing epoch number.",
  "error parsing general logfile name.",
  "error parsing stream 1 notification file name.",
  "error parsing stream 2 notification file name.",
  "error parsing stream 3 notification file name.", /* 15 */
  "error parsing stream 4 notification file name.",
  "error parsing time difference",
  "Error parsing coincidence time.",
  "error parsing servo parameter.",
  "Error parsing protocol index.", /* 20 */
  "protocol out of range (0..2)",
  "Cannot malloc stream-1 buffer.",
  "Cannot malloc stream-2 buffer.",
  "Cannot malloc stream-3 buffer.",
  "Cannot malloc stream-4 buffer.", /* 25 */
  "Error opening main logfile.",
  "error opening notification stream 1",
  "error opening notification stream 2",
  "error opening notification stream 3",
  "error opening notification stream 4", /* 30 */
  "error opening source stream 1", 
  "error opening source stream 2", 
  "error opening target stream 3", 
  "error opening target stream 4", 
  "no target mode defined for type-1 packets.", /* 35 */
  "no target mode defined for type-2 packets.",
  "no target mode defined for type-3 packets.",
  "no target mode defined for type-4 packets.",
  "No content reading stream 1.",
  "General I/O error reading stream 1.", /* 40 */
  "incomplete read on stream 1.",
  "wrong stream type detected when looking for stream-1.",
  "stream 1 inconsistency detected.",
  "No content reading stream 2.",
  "General I/O error reading stream 2.", /* 45 */
  "incomplete read on stream 2.",
  "wrong stream type detected when looking for stream-2.",
  "stream 2 inconsistency detected.",
  "unexpexted end of stream 2.",
  "error removing stream 1 file.", /* 50 */
  "error removing stream 2 file.",
  "cannot malloc decision table",
  "cannot write type-4 header",
  "cannot write type-4 content",
  "cannot write type-3 header", /* 55 */
  "cannot write type-3 data",
  "cannot convert compression filter constant.",
  "filter constant in -R option out of range.",
  "cannot convert stream-4 bitwidth",
  "stream-4 bitwidth in -r out of range ", /* 60 */
  "error converting zeroevent policy argument.",
  "zeroevent policy parameter out of range (0..2)",
  "mismatch between expected and transmitted bits in stream 2.",
  "access failed nonexpectedly",
  "error parsing flushmode",  /* 65 */
  "flushmode out of range",
  "error parsing accidental measurement window distance",
  "Error opening histogram file",
  "error reading histogram length or value not >0",
  "error reading histogram base name", /* 70 */
  "cannot stat stream 2 handle",
  "Error reading file/directory name for type-3 Bell packets.",
  "duplicate definition of type-5 file.",
  "Cannot malloc stream-5 buffer (Bell measurement)",
  "no target mode defined for type-5 packets.",   /* 75 */
  "error opening notification stream 5",
  "error opening target stream 5",
  "cannot write type-5 header",
  "cannot write type-5 data",  
  "wrong skew format. needs -S v1,v2,v3,v4", /* 80 */
};

int emsg(int code) {
  fprintf(stderr,"%s\n",errormessage[code]);
  return code;
};

/* tables etc. */
int openmode[6] = {0,O_RDONLY,O_RDONLY, /* modes for stream 1 and 2 */
		   O_WRONLY | O_TRUNC | O_CREAT, /* mode 3 */
		   O_WRONLY | O_TRUNC | O_CREAT, /* mode 4 */
		   O_WRONLY | O_TRUNC | O_CREAT, }; /* mode 5 */

#define FILE_PERMISSIONS 0644  /* for all output files */


/* global variables for IO handling */
int verbosity_level = DEFAULT_VERBOSITY;
int zeropolicy = DEFAULT_ZEROPOLICY; /* what to do on no events */
char fname[6][FNAMELENGTH]={"","","","","",""}; /* stream files */
char logfname[5][FNAMELENGTH]={"","","","",""}; /* all different logfiles */
FILE* loghandle[5]; /* for log files */
struct header_1 head1; /* infile header */
struct header_2 head2; /* infile header */
struct header_3 head3; /* raw key file header */
struct header_4 head4; /* confirmation file header */
struct header_3 head5; /* Bell file output */
char ffnam[FNAMELENGTH+10], ffn2[FNAMELENGTH+10];
int typemode[6]={0,0,0,0,0,0}; /* no mode defined. other types:
		 		  1: single file, 2: directory save, ... */
int killmode[3] = {0,DEFAULT_KILLMODE1,
		   DEFAULT_KILLMODE2 }; /* if !=1, delete infile after use */
int handle[6]; /* global handles for packet streams */

unsigned int ecnt1, ecnt2,ecnt1initial; /* event counter for input streams */
unsigned int sendword3,sendword4,sendword5; /* for writing to stream 3 to 5 */
int index3,index4,index5,type3datawidth,type4datawidth,type5datawidth;
int type4bitwidth = DEFAULT_STREAM4BITWIDTH; /* for packer */ 
int type4bitwidth_long; /* for servo, value times 256  */
int filterconst_stream4 = DEFAULT_FILTERCONST_4; /* for stream4 compression */
int bitstosend4,resbits3,resbits4,resbits5;
unsigned int tdiff4_bitmask;
unsigned int *outbuf3, *outbuf4, *outbuf5;
unsigned int idiff4_bitmask;  /* detecting exception words */
int thisepoch_converted_entries; /* coincidences with basematch */
int thisepoch_siftevents; /* counts total entries in the target4 file */
int thisepoch_testevents; /* counts number of testevents. used for
			     distinguishing test- and keyevents */
int uepoch; /* which type of stream file from stream 2 */
long int ft; /* for monitoring */
unsigned int accidentals,truecoincies;
int expected2bits; /* bits expected from the stream-2 packets */
int flushmode = DEFAULT_FLUSHMODE; /* for tracking flushmode */

/* lookup table for correction of epoch in strem 1 */
#define PL1 0x10000  /* +1 step fudge correction for epoc index mismatch */
#define MI1 0xffff0000 /* -1 step fudge correction */
#define MI2 0xfffe0000 /* -2 step fudge correction */
unsigned int overlay_correction[16]= {0,PL1,MI2,MI1, MI1,0,PL1,MI2,
				      MI2,MI1,0,PL1, PL1,MI2,MI1,0};



/* opening routine to target files stream 3 and 4 and (optionally) 5 */
int open_epoch(unsigned int ep) { /* parameter is new epoch */
  
    /* populate headers preliminary */
    head3.tag = uepoch?TYPE_3_TAG_U:TYPE_3_TAG; head3.length = 0;
    head3.epoc = ep; head3.bitsperentry = type3datawidth;

    head4.tag = uepoch?TYPE_4_TAG_U:TYPE_4_TAG; head4.length = 0;
    head4.epoc = ep;
    head4.timeorder = type4bitwidth; head4.basebits = type4datawidth;
    fprintf(debuglog,"costream: type4bitwidth: %d for epoch %08x\n",
	    type4bitwidth,ep); fflush(debuglog);

    /* initialize output buffers and temp storage*/
    index3=0;sendword3=0;resbits3=32;
    index4=0;sendword4=0;resbits4=32;

    /* optionally open stream 5 (Bell measurement results) */
    head5.tag = uepoch?TYPE_3_TAG_U:TYPE_3_TAG; head5.length = 0;
    head5.epoc = ep; head5.bitsperentry = type5datawidth;
    index5=0;sendword5=0;resbits5=32;

    return 0;
}

/* flush output buffers and submit files */
int close_epoch() {
    char ffnam_c[FNAMELENGTH+10];
    int retval,i,optimal_width;
    unsigned int average_distance; /* for stream4 compress optimizer */
    unsigned int t4a;
    int te = head3.epoc; /* holds this epoch */
    
    if (thisepoch_siftevents || zeropolicy) { /* emit stream-4 files */
	/* finish stream 4 entries */
	t4a = TYPE_4_ENDWORD<<type4datawidth;
	
	/* save timing and transmit bits */
	if (resbits4>=bitstosend4) {
	    sendword4 |= (t4a << (resbits4-bitstosend4));
	    resbits4 = resbits4-bitstosend4;
	    if (resbits4==0) { 
		outbuf4[index4++]=sendword4;
		sendword4=0;resbits4=32;
	    }
	} else {
	    resbits4=bitstosend4-resbits4;
	    sendword4 |= (t4a >> resbits4);
	    outbuf4[index4++]=sendword4;
	    resbits4=32-resbits4;
	    sendword4=t4a << resbits4;
	}
	
	/* write out last word */
	if (resbits4<32) outbuf4[index4++]=sendword4;
	head4.length = thisepoch_siftevents; /* update header */
	
	/* eventually open stream 4 */
	switch (typemode[4]) {
	    case 2: /* file in directory */
		strncpy(ffnam_c, fname[4], FNAMELENGTH);
		atohex(&ffnam_c[strlen(ffnam_c)],head4.epoc);
		handle[4]=open(ffnam_c,openmode[4],FILE_PERMISSIONS);
		if(-1==handle[4]) return 34;
		break;
	}

	/* write header 4 and content */
	retval=write(handle[4],&head4,sizeof(struct header_4));
	if (retval!=sizeof(struct header_4)) return 53;  /* cannot write header */
	i=index4*sizeof(unsigned int);
	retval=write(handle[4],outbuf4,i);
	if (retval!=i) return 54; /* cannot write content */
	
	/* eventually close stream 4 */
	switch (typemode[4]) {
	    case 2:
		close(handle[4]);
		break;
	}

	/* servo loop for optimal compression parameter of stream 4 */
	if (thisepoch_siftevents) {
	    average_distance = 
		ecnt2 / thisepoch_siftevents;
	    if (average_distance<8) average_distance=8;
	    optimal_width= 
		(int) ((log((float)average_distance)/log(2.)+2.2117)*16.);
	    /* do integer version of (log(agv)/log(2)+2.2117)*16 */
	    /*tmp=average_distance;optimal_width=0;
	      while (tmp>31) {tmp /=2; optimal_width++;};
	      optimal_width = optimal_width*16+log_correcttable[tmp&0xf];*/
	    if (filterconst_stream4) {
		type4bitwidth_long +=
		    (optimal_width*16-type4bitwidth_long)/filterconst_stream4;
		type4bitwidth=type4bitwidth_long>>8;
		/* avoid overshoot */
		if (type4bitwidth<MIN_4_BITWIDTH) type4bitwidth=MIN_4_BITWIDTH;
		if (type4bitwidth>MAX_4_BITWIDTH) type4bitwidth=MAX_4_BITWIDTH;
		fprintf(debuglog,"loop: t4long: %d, optimal_width: %d, avg_dist: %d filterconst: %d, def: %d\n",type4bitwidth_long,optimal_width,average_distance,filterconst_stream4,DEFAULT_FILTERCONST_4);
	    };
	    idiff4_bitmask = (1<<type4bitwidth)-1; /* for packing */
	}

	/* notify stream 4 */
	if (logfname[4][0]) fprintf(loghandle[4],"%08x\n",te);
	if (flushmode>0) fflush(loghandle[4]);
    }

    /* keep this updated */
    bitstosend4=type4bitwidth+type4datawidth; /* has to be <32 */

    if (thisepoch_siftevents || (zeropolicy>1)) { /* emit stream-3 and -5 */
	/* flush stream 3, write the length and close it */
	if (resbits3<32) outbuf3[index3++]=sendword3;
	head3.length = thisepoch_siftevents-thisepoch_testevents;

	/* eventually open stream 3 */
	switch (typemode[3]) {
	    case 2: /* file in directory */
		strncpy(ffnam_c, fname[3], FNAMELENGTH);
		atohex(&ffnam_c[strlen(ffnam_c)],head3.epoc);
		handle[3]=open(ffnam_c,openmode[3],FILE_PERMISSIONS);
		if(-1==handle[3]) return 33;
		break;
	}
	
	/* write header 3 */
	retval= write(handle[3],&head3,sizeof(struct header_3));
	if (retval!=sizeof(struct header_3)) return 55; /* write error */
	i=index3*sizeof(unsigned int);
	retval=write(handle[3],outbuf3,i);
	if (retval!=i) return 56; /* write error buffer */
	

	/* eventually close stream 3 */
	switch (typemode[3]) {
	    case 2:
		close(handle[3]);
	}

	/* eventually do stream 5 */
	if (typemode[5]) { /* only generate this if necessary */
	 	if (resbits5<32) outbuf5[index5++]=sendword5;
		head5.length = thisepoch_testevents;

		/* eventually open stream 5 */
		switch (typemode[5]) {
		    case 2: /* file in directory */
			strncpy(ffnam_c, fname[5], FNAMELENGTH);
			atohex(&ffnam_c[strlen(ffnam_c)],head5.epoc);
			handle[5]=open(ffnam_c,openmode[5],FILE_PERMISSIONS);
			if(-1==handle[5]) return 77;
			break;
		}
	
		/* write header 5 */
		retval= write(handle[5],&head5,sizeof(struct header_3));
		if (retval!=sizeof(struct header_3)) return 78; /* writ err */
		i=index5*sizeof(unsigned int);
		retval=write(handle[5],outbuf5,i);
		if (retval!=i) return 79; /* write error buffer */
		
		
		/* eventually close stream 5 */
		switch (typemode[5]) {
		    case 2:
			close(handle[5]);
			break;
		}
		
	}
	
	/* notify stream 3 */
	if (logfname[3][0]) fprintf(loghandle[3],"%08x\n",te);
	if (flushmode>1) fflush(loghandle[3]);
    }
    /* logging to general file */
    if (verbosity_level>=0) {
	switch (verbosity_level) {
	    case 0: /* bare hex names of received streams */
		fprintf(loghandle[0],"%08x\n",te);
		break;
	    case 1: /* log length w/o text and epoch */
		fprintf(loghandle[0],"%08x\t%d\n",
			te,thisepoch_siftevents);
		break;
	    case 2: /* log length w text and epoch */
		fprintf(loghandle[0],
			"epoch: %08x\t survived raw entries: %d\n",
			te,thisepoch_siftevents);
		break;
	    case 3: /* log length w text and epoch and setbits */
		fprintf(loghandle[0],
			"epoch: %08x, stream2 evnts: %d, stream4 evnts: %d, new bitwidth4: %d\n",
			te, ecnt2, thisepoch_siftevents,type4bitwidth);
		break;
	    case 4: /* log epoch, inlength, outlength, bitwidth for output,
		       servoed time difference, est accidentals, accepted
		       coincidences w text */
		fprintf(loghandle[0],
			"epoch: %08x, 2-evnts: %d, 4-evnts: %d, new bw4: %d, ft: %li, acc: %i, true: %i, 1-events: %d\n",
			te, ecnt2, thisepoch_siftevents,type4bitwidth,
			ft,accidentals,truecoincies,ecnt1initial);
		break;
	    case 5: /* log as in verbo mode 4 but without text */
		fprintf(loghandle[0], "%08x\t%d\t%d\t%d\t%li\t%i\t%i\t%i\n",
			te, ecnt2, thisepoch_siftevents,type4bitwidth,ft,
			accidentals,truecoincies,ecnt1initial);
		break;

	}
	if (flushmode>1) fflush(loghandle[0]); /* main log flush */	
    }

    /* logging to notification files/streams 1 and 2  */
    for (i=1;i<3;i++) if (logfname[i][0]) {
	fprintf(loghandle[i],"%08x\n",te);
	if (flushmode>2) fflush(loghandle[i]);
    }

    /* emit histogram if defined and due */
    if (histologname[0]) {
	histos_to_go--;
	if (!histos_to_go) 
	    emit_histo(te);
    }
    return 0;
}


/* function to fill buffer with stream-1 raw data. eats an input bufferpointer,
   a file handle, a max size in bytes, and a pointer to a header_1 struct.
   returns an error code.  */ 
int get_stream_1(void *buffer, int handle, int maxsize,
		 struct header_1 *head) {
    int retval;
    int eidx;
    int loops, bytelen; /* read-in game variables */
    unsigned int *ib = buffer;
    struct header_1 *h; /* for local storage */

    retval=read(handle,buffer,maxsize);
    if (!retval) return 39; /* nothing available */
    if (!(retval+1)) return 40; /* other error */
    if (retval<(int)sizeof(struct header_1)) return 41; /* incomplete read */
    h=(struct header_1 *)buffer; /* at beginning of stream */
    /* consistency check at end */
    if ((h->tag!=TYPE_1_TAG) && (h->tag!=TYPE_1_TAG_U)) return 42;
    if (h->length) {
	eidx=(h->length*sizeof(struct rawevent)+sizeof(struct header_1))
	    /sizeof(unsigned int);
	if (eidx!=(retval/(int)sizeof(unsigned int)-2)) {
	    /* we did not get everything */
	    bytelen = retval; /* save number of already loaded bytes */
	    for (loops=DEFAULT_READLOOPS;loops>0;loops--) {
		retval=read(handle,&((char *)buffer)[bytelen],maxsize-bytelen);
		if (!(retval+1)) return 40; /* other error */
		bytelen +=retval;
		if (bytelen >= (h->length+1)*sizeof(struct rawevent) +
		    sizeof(struct header_1)) break; /* got all or more? */ 
		usleep(DEFAULT_SLEEP_LOOP); /* sleep a while */
	    }
	    if (!loops) {
		fprintf(stderr,
			"stream 1 ep %08x bytes shortage; got %d len:%d\n",
			h->epoc, bytelen, h->length);
		return 41;
	    } 
	}
	if (ib[eidx] | ib[eidx+1]) return 43; /* last word nonzero */

    } else {
	fprintf(stderr,"stream 1 ep %08x zero announced len, got %d bytes\n",
		h->epoc, retval);
	if (retval-sizeof(struct header_1) % sizeof(struct rawevent))
	    return 43; /* size mismatch */
	eidx=retval/sizeof(unsigned int);
	if (ib[eidx-1] |ib[eidx-2]) return 43; /* last word nonzero */
	if (!(ib[eidx-3] |ib[eidx-4])) return 15; /* last real entry zero */ 
	h->length=
	    (retval-sizeof(struct header_1))/sizeof(struct rawevent)-1;
    }
    ecnt1initial=h->length;
    *head=h[0]; /* return pointer to header */
    return 0;
}

/* function to fill buffer with stream-2 raw data. eats an input buffer, a
   file handle, a max size in bytes, and a pointer to a header_2 structure.
   returns an error code. */
int get_stream_2(void *buffer, int handle, int maxsize, 
		 struct header_2 *head, int* realsize) {
    int retval, bytelen,loops;
    int upper,lower; /* for consistency check */
    struct header_2* h;
    struct stat stbf; /* holds stat information */
   
    /* get stat of file */
    if (fstat(handle,&stbf)) {
	fprintf(stderr, "errno: %d ",errno);
	return 71; 
    }
    /* do stat test if you can, i.e., ordinary file */
    if (S_ISREG(stbf.st_mode)) { /* can use stat info to get length */
	bytelen=0;
	for (loops=DEFAULT_READLOOPS;loops>0;loops--) {
	    retval=read(handle,&((char *)buffer)[bytelen],maxsize-bytelen);
	    if (!(retval+1)) return 45; /* other error */
	    bytelen +=retval;
	    if (bytelen>=stbf.st_size) break; /* got all bytes - or more?? */
	    usleep(DEFAULT_SLEEP_LOOP); /* sleep a while */
	}
	if (!loops)  { /* failed to read all bytes */
	    fprintf(stderr, "cannot get all bytes; got %d ",bytelen);
	    return 46; /* incomplete read */
	}
    } else { /* need to hope that I get correct length in first read */
	retval=read(handle,buffer,maxsize);
	if (!(retval+1)) return 45; /* other error */
	bytelen= retval;
    }
    if (!retval) return 44; /* nothing available */
   
    if (bytelen<(int)sizeof(struct header_2)) return 46; /* incomplete read */
    h=(struct header_2 *)buffer; /* at beginning of stream */
    /* consistency check on length and tag */
    if ((h->tag!=TYPE_2_TAG) && (h->tag!=TYPE_2_TAG_U)) return 47;
    if (h->length) {
        lower=(sizeof(struct header_2)*8+
	       (h->length+1)*(h->basebits+h->timeorder))/8;
	upper=(sizeof(struct header_2)*8+
	       (h->length+1)*(h->basebits+h->timeorder+32)+31)/8;

	/* bitnum=((retval-sizeof(struct header_2))*8-h->basebits-
	   h->timeorder-31)/h->length - h->basebits-h->timeorder; */
	if ((lower>bytelen) | (upper<bytelen)) {
	     fprintf(stderr, "retval: %d, len (elems): %d, len (stat): %ld, bytelen: %d, u:%d, l:%d\n",
		   retval,h->length, stbf.st_size, bytelen,upper,lower);
		  
	    return 48;}
    }
    /* protocol bit match? */
    if (h->basebits != expected2bits) {
	fprintf(stderr,"base: %d, expected: %d\n",h->basebits, expected2bits);
	return 63;
    }
    *realsize = bytelen; /* read in bytes */
    *head=h[0];
    return 0;
}



int main (int argc, char *argv[]) {
    unsigned int startepoch = DEFAULT_STARTEPOCH; /* epoch to start with */
    unsigned int epochnumber = DEFAULT_EPOCHNUMBER; /* # of epochs to read  */
    long long int se_in; /* for entering startepoch both in hex and decimal */
    int firstrun = 0; /* first run of reading stream 2 - no close 3,4 */
    long long int timediff0 = 17; /* initial time difference */
    long long int timediff = 18; /* current time difference */
    long long int eventdiff = 0;
    long long hdiff; /* for histogramming */
    unsigned long long int t1=0, t2=0, t1old=0; /* extracted times  */
    long long int coincwindow = DEFAULT_COINCWINDOW; /* in 1/8 nsec */
    long long int trackwindow = DEFAULT_TRACKWINDOW; /* in 1/8 nsec */
    int accidental_dist = DEFAULT_ACCDIST; /* in 1/8 nsec */
    long long int referencewindow1,referencewindow2;
    long long int floattime;  /* floating avg time difference in 1/8/4096 */
    long long int servodiff; /* time since last servo event */
    unsigned long long int lastservotime; /* for time-based servoing */
    long long int servoofftime=MAX_SERVOOFFTIME; /* prevent jumps */
    int servo_param = DEFAULT_FILTER; /* time/event const for tracker */
    long long int servo_p1 = 0; /* reduce calculation in filter */
    int proto_index = DEFAULT_PROTOCOL; /* defines which proto is used */
    char *buffer1, *buffer2; /* stream buffers */
    int getone, gettwo;  /* for coincidence loop */

    unsigned int epoch1, epoch2; /* running epochs for read/write */
    struct rawevent *pointer1; /* for parsing stream-1 */
    unsigned int localep; /* for initializing stream 1  epoch */
    unsigned long long epoch1_offset = 0; /* for epoch correction */
    int pattern1;
    int raw_patternmask; /* which detectors to take; */

    int realsize2; /* entries in buffer2 */
    unsigned int *pointer2=NULL; /* for parsing stream-2 */
    int idx2=0,resbits2=0,type2bitwidth=0,type2datawidth=0; /* for buffer2 */
    int bitstoread2=0;
    int emergency_break,pattern2=0,opatt2;
    unsigned long long tdiff_bitmask2=0,patternmask2=0;
    unsigned int tdiff2,readword2=0;

    int *decisionmatrix; /* contains the protocol decision at this level */
    int decisionindexmask,keepthatpairmask,stream4datashift;
    int longerpattern;  /* the longer of stream 3 or stream 5 bitlengths */
    int testeventmask;  /* to mask out the decision test/key */
    int stream4datamask, stream3datamask, stream5datamask;
    int stream3data, stream4data, stream5data;

    unsigned int oldindex4=0; /* for saving index */
    unsigned int indexdiff4,t4,t4a; /* temporary variable for timedifference */
    int opt,i,j,retval,d;
    int opcnt;  /* limit counter for file waiting */
    int skewcorrectmode=0; /* now detector de-skew */
    int dskew[8]; /* detector deskew registers */
    long long int skewtab[16];
   
    
    /* parsing options */
    opterr=0; /* be quiet when there are no options */

    debuglog=fopen("costream_tlog","w+");
    fprintf(debuglog,"this run filtercionst4: %d, width: %d\n",
	    filterconst_stream4,type4bitwidth);


    while ((opt=getopt(argc, argv, "V:F:f:d:D:O:o:i:I:kKe:q:Q:M:m:L:l:n:t:w:u:r:R:p:T:G:a:h:H:S:b:B:")) != EOF) {
	i=0; /* for setinf names/modes commonly */
	/* fprintf(debuglog,"got option >>%c<<, filter: %d, width: %d\n",
	   opt,filterconst_stream4,type4bitwidth); */
	switch (opt) {
	    case 'V': /* set verbosity level */
		if (1!=sscanf(optarg,"%d",&verbosity_level)) return -emsg(1);
		break;
		/* a funky way of parsing all file name options together.
		   i contains the stream in the two lsb, and the mode in the
		   lsb. */
	    case 'F': i++; /* stream 4, directory */
	    case 'f': i++; /* stream 3, directory */
	    case 'd': i++; /* stream 2, directory */
	    case 'D': i++; /* stream 1, directory */
 	    case 'O': i++; /* stream 4, file */
 	    case 'o': i++; /* stream 3, file */
 	    case 'i': i++; /* stream 2, file */
 	    case 'I':      /* stream 1, file */
		j=(i&3)+1; /* stream number */
		if (1!=sscanf(optarg,FNAMFORMAT,fname[j])) return -emsg(1+j);
		fname[j][FNAMELENGTH-1]=0;   /* security termination */
		if (typemode[j]) return -emsg(5+j); /* already defined mode */
		typemode[j]=(i&4?2:1);
		break;
	    case 'B': i++;/* stream3 directory for BELL mesaurement */
	    case 'b': /* stream3 file for BELL mesaurement */
		j=5; /* stream number */
		if (1!=sscanf(optarg,FNAMFORMAT,fname[j])) return -emsg(72);
		fname[j][FNAMELENGTH-1]=0;   /* security termination */
		if (typemode[j]) return -emsg(73); /* already defined mode */
		typemode[j]=((i&1)?2:1); /* dirctory/file distinguisher */ 
		break;
	    case 'k': /* kill mode stream 2 */
		killmode[2]=1;
		break;
	    case 'K':/* kill mode stream 1 */
		killmode[1]=1;
		break;
	    case 'e': /* read startepoch */
		if (1!=sscanf(optarg,"%lli",&se_in)) return -emsg(10);
		startepoch=se_in & 0xffffffff;
		break;
	    case 'q': /* read epoch number */
		if (1!=sscanf(optarg,"%d",&epochnumber)) return -emsg(11);
		break;
	    case 'Q': /* choose filter factor for coincidence tracker */
		if (1!=sscanf(optarg,"%d",&servo_param)) return -emsg(19);
		break;
            /* parsing logfile names 0 (main) and 1,2,3,4 */
	    case 'M': i++; /* stream 4 notification */
	    case 'm': i++; /* stream 3 notification */
	    case 'L': i++; /* stream 2 notification */
	    case 'l': i++; /* stream 1 notification */
	    case 'n':      /* global logfile name */
		if (sscanf(optarg,FNAMFORMAT,logfname[i]) != 1)
		    return -emsg(12+i);
		logfname[i][FNAMELENGTH-1]=0;  /* security termination */
		break;
	    case 't': /* read in timedifference */
		if (1!= sscanf(optarg,"%lli",&timediff0)) return -emsg(17);
		break;
	    case 'w': /* coincidence time window */
		if (1!= sscanf(optarg,"%lld",&coincwindow)) return -emsg(18);
		break;
	    case 'u': /* tracking time window */
		if (1!= sscanf(optarg,"%lld",&trackwindow)) return -emsg(18);
		break;
	    case 'r': /* intitial stream-4 bitlength */
		if (1!= scanf(optarg,"%i",&type4bitwidth)) return -emsg(59);
		if ((type4bitwidth<MIN_4_BITWIDTH) ||
		    (type4bitwidth>MAX_4_BITWIDTH)) return -emsg(60);
		break;
	    case 'R': /* timedifference servo filter for stream-4 packer */
		if (1!= sscanf(optarg,"%i",&filterconst_stream4)) 
		    return -emsg(57);
		if (filterconst_stream4<0) return -emsg(58);
		break;
	    case 'p': /* protocol index */
		if (1!= sscanf(optarg,"%i",&proto_index)) return -emsg(20);
		if ((proto_index<0) || (proto_index>PROTOCOL_MAXINDEX))
		    return -emsg(21);
		break;
	    case 'T': /* zeroevent policy */
		if (1!=sscanf(optarg,"%i",&zeropolicy)) return -emsg(61);
		if ((zeropolicy<0) || (zeropolicy>2)) return -emsg(62);
		break;
	    case 'G': /* define flushmode */
		if (1!=sscanf(optarg,"%i",&flushmode)) return -emsg(65);
		if ((flushmode<0) || (flushmode>3)) return -emsg(66);
		break;
	    case 'a': /* accidental coincidence distance */
		if (1!=sscanf(optarg,"%i",&accidental_dist)) return -emsg(67);
		break;
	    case 'h': /* get num of epochs per histogram */
		if (1!=sscanf(optarg,"%i",&histolen)) return -emsg(69);
		if (histolen<1) return -emsg(69);
		fprintf(debuglog,"entered histolen: %d\n",histolen);
		break;
	    case 'H': /* histogram name */
		if (sscanf(optarg,FNAMFORMAT,histologname) != 1)
		    return -emsg(70);
		break;
	    case 'S': /* detector skew correction */
	        if (4!=sscanf(optarg,"%d,%d,%d,%d", &dskew[0],&dskew[1],
			      &dskew[2],&dskew[3])) return -emsg(80);
		skewcorrectmode =1;
		break;

	    default: /* something fishy */
		fprintf(debuglog,"got code I should not get: >>%c<<\n",opt);
		break;
	}
    }

    /* check argument consistency */
    fprintf(debuglog,"after parsing filterconst4: %d, width: %d\n",
	    filterconst_stream4,type4bitwidth);

    /* eventually initiate histogram */
    if (histologname[0]) init_histo();

    /* initiate skew correction for t1 files */
    for (i=0;i<16;i++) skewtab[i]=0;
    if (skewcorrectmode==1) {
      for (i=0;i<4;i++) skewtab[1<<i]=dskew[i];
    }


    /* to estimate background */
    referencewindow2=accidental_dist;
    referencewindow1=accidental_dist-coincwindow*2;
    /* prepare servo parameters for coincidence tracker */
    if (servo_param>0) 
	servo_p1 = SERVO_GRANULARITY/servo_param; /* event-based filter */
    if (servo_param<0) {
	servo_p1 = -((long long int)servo_param)*
	    SERVO_BASETIME/SERVO_GRANULARITY;
	servoofftime=-1*(long long int)servo_param*SERVO_BASETIME; /* avoid overshoots */
	/* forget servoing for cnt rate below max_servoofftime */
	if (servoofftime>MAX_SERVOOFFTIME) servoofftime=MAX_SERVOOFFTIME;
    }
    lastservotime=0; /* initialize servo first */
    
    
    /* initialize bitwidth servo for stream 4 */
    type4bitwidth_long = type4bitwidth<<8; /* servo variable */
    idiff4_bitmask = (1<<type4bitwidth)-1; /* for packing */

    /* allocate input and output buffers */
    if (!(buffer1=(char*)malloc(RAW1_SIZE))) return -emsg(22);
    if (!(buffer2=(char*)malloc(RAW2_SIZE))) return -emsg(23);
    if (!(outbuf3=(unsigned int *)malloc(RAW3_SIZE))) return -emsg(24);
    if (!(outbuf4=(unsigned int *)malloc(RAW4_SIZE))) return -emsg(25);
    if (!(outbuf5=(unsigned int *)malloc(RAW3_SIZE))) return -emsg(74);

    /* for processing stream 1 */
    pointer1=(struct rawevent *)(buffer1+sizeof(struct header_1));

    /* protocol preparation */
    i=proto_table[proto_index].decsize; /* size of array */
    if (!(decisionmatrix=(int*)malloc(i*sizeof(int)))) return -emsg(52);
    proto_table[proto_index].fill_decision(decisionmatrix);

    /* find longer of -3 or -5 pattern */
    longerpattern = proto_table[proto_index].bitsperentry3;
    if (longerpattern <	proto_table[proto_index].bitsperentry5) 
	longerpattern = proto_table[proto_index].bitsperentry5;

    keepthatpairmask= (1<<(longerpattern +
			   proto_table[proto_index].bitsperentry4));
    testeventmask = keepthatpairmask <<1; /* for Bell tests */

    decisionindexmask=(1<<(proto_table[proto_index].expected2bits+4))-1;

    expected2bits=proto_table[proto_index].expected2bits; /* consistency tst */
    /* what detectors to expect */
    raw_patternmask=proto_table[proto_index].detectorentries-1;

    stream3datamask=(1<<proto_table[proto_index].bitsperentry3)-1;
    stream5datamask=(1<<proto_table[proto_index].bitsperentry5)-1;

    type3datawidth=proto_table[proto_index].bitsperentry3;
    type5datawidth=proto_table[proto_index].bitsperentry5;

    stream4datashift=longerpattern;
    stream4datamask=((1<<proto_table[proto_index].bitsperentry4)-1)<<
	stream4datashift;
    type4datawidth =proto_table[proto_index].bitsperentry4;
    bitstosend4=type4bitwidth+type4datawidth; /* has to be <32 !! */


    /* open logfile streams */
    for (i=0;i<5;i++) {
	if (logfname[i][0]) { /* check if filename is defined */
	    loghandle[i]=fopen(logfname[i],"a");
	    if (!loghandle[i]) return -emsg(26+i);
	} else if (!i) {loghandle[i] = stdout;} /* use stdout for standard */
    }
    /* evtl. open stream files */
    for (i=1;i<6;i++) { /* allow for non-definition of stream-5 mode */
	switch (typemode[i]) {
	    case 0: /* no mode defined */
		if (i<5) return -emsg(34+i); /* need this file but no mode */
		/* now we are at stream 5 */
		if (proto_index==3 || proto_index==4) {
		    return -emsg(75);
		}
		break;
	    case 1: /* single file */
		handle[i]=open(fname[i],openmode[i],FILE_PERMISSIONS);
		if (-1==handle[i]) return -emsg(30+i);
	}
    }

    /* prepare input/output buffers to be loaded */
    head1.length=0; head2.length=0; /* emty buffers initially */
    ecnt1=0; ecnt2=0;/* number of already processed events */
    epoch1 = startepoch; /* epochs to read */
    epoch2 = startepoch; /* epoch to read and master epoch for write */
    getone=1; gettwo=1; /* mark for colletion */
    timediff=timediff0;  /* start with initial time difference */
    floattime=0; /* coincidence tracker hires state variable */
    firstrun=1; /* to read in stream-2 without saving streams 3,4 */
    thisepoch_converted_entries=0;
    thisepoch_siftevents=0;  /* what ends up in the target files */
    thisepoch_testevents=0;  /* no testevents so far */
    accidentals=0;truecoincies=0;

    /* initialize to avoid 38 yr overrun */
    t1=(unsigned long long)(startepoch-1)<<32; t2=t1; t1old=t1;
    /* main digest loop */
    while (1) {
	eventdiff=((long long int)(t1-t2))+timediff;
	if (eventdiff<-trackwindow || getone) {
	    /* load event 1 */
	    if (ecnt1==head1.length) { /* time to reload a stream-1 package */
		/* evtl. open stream 1 */
		if (typemode[1]==2) { /* file in directory */
		    strncpy(ffnam, fname[1], FNAMELENGTH);
		    atohex(&ffnam[strlen(ffnam)],epoch1);

		    opcnt=MAXFILETESTS;
 		    while ((retval=access(ffnam,R_OK))) { 
 			if (errno != ENOENT) {
			    fprintf(stderr,"file(1):%s,errno:%d",ffnam,errno);
			    return -emsg(64);
			}
			if (!(opcnt--)) {
			    fprintf(stderr,"waited too long for %s;",ffnam);
			    return -emsg(31);
			}
			usleep(DEFAULT_WAITFORFILE);
 		    } 
		    usleep(DEFAULT_WAITWRITTEN);
		    
		    handle[1]=open(ffnam,openmode[1]);
		    if(-1==handle[1]) return -emsg(31);

		}
		/* buffer stream 1 */
		retval=get_stream_1(buffer1,handle[1],RAW1_SIZE,&head1);
		if (retval) return -emsg(retval);
		/* check epoch consistency */
		if (head1.epoc!=epoch1) return -emsg(43);
		/* evtl close stream 1 */
		if (typemode[1]==2) { /* file is not a  directory */
		    close(handle[1]);
		    /* eventually remove file */
		    if (killmode[1] && (handle[1]!=0)) {
			if (unlink(ffnam)) return -emsg(50);
		    }
		}

		/* adjust absolute epoch */
		localep=(pointer1[0].cv)>>15; /* from timestamp unit */
		/* take upper 17 bit from epoch for offset */
		epoch1_offset=(unsigned long long)
		      ((epoch1 & 0xffff8000)-(localep & 0x00018000))<<32;
		ecnt1=0; /* reset for this round */
		/* printf("ep1: %08x, local %x ofs: %llx\n", 
		   epoch1,localep,epoch1_offset>>32); */
		epoch1++;
	    }
	    /* get a value out of the list */
	    t1old=t1;
	    t1=((unsigned long long)pointer1[ecnt1].cv<<17)
		+(pointer1[ecnt1].dv>>15)+epoch1_offset
	        + skewtab[(pointer1[ecnt1].dv & 0x0f)]; /* current timing */
	    if (t1<=t1old) { /* something's fishy. ignore this value */
		ecnt1++;
		t1=t1old;
		getone=1;
		continue;
	    }
	    /* get pattern 1 later... */
	    ecnt1++;
	    getone=0;
	    continue;
	}
	if ((eventdiff>referencewindow2)|| gettwo) { /* clearly out-of-band */
	    /* load event 2 */
	    if (ecnt2>=head2.length) { /* time to reload a stream-2 package */
		/* eventually save streams 3 and 4 */
		if (!firstrun) {
		    /* save stream 3 and 4, and do logging */
		    close_epoch();
		}
		
		/* check termination of this epoch for -q option */
		if (epochnumber && (epoch2>=startepoch+epochnumber)) {
		    break;
		}
		
		/* evtl. open stream 2 */
		if (typemode[2]==2) { /* file in directory */
		    strncpy(ffn2, fname[2], FNAMELENGTH);
		    atohex(&ffn2[strlen(ffn2)],epoch2);
		    opcnt=MAXFILETESTS;
 		    while ((retval=access(ffn2,R_OK))) { 
 			if (errno != ENOENT) { /* file does not exist */
			    fprintf(stderr,"file(2):%s,errno:%d",ffn2,errno);
			    return -emsg(64);
			}
			if (!(opcnt--)) {
			    fprintf(stderr,"timeout for %s",ffn2);
			    return -emsg(32);
			}
			usleep(DEFAULT_WAITFORFILE);
 		    } 

		    handle[2]=open(ffn2,openmode[2]);
		    if(-1==handle[2]) {
			fprintf(stderr,"real open fail: errno %d ",errno);
			return -emsg(32);
		    }
		}

		/* buffer stream 2 */
		retval=get_stream_2(buffer2,handle[2],RAW2_SIZE,&head2,
				    &realsize2);
		if (retval) return -emsg(retval);

		/* check epoch consistency */
		if (head2.epoc!=epoch2) return -emsg(48);
		if (firstrun) {
		    uepoch=(head2.tag==0x102?1:0);
		    firstrun=0;
		}
		
		/* close evtl stream 2 */ 
		if (typemode[2]==2) { /* file is in a directory */
		    close(handle[2]);
		    /* eventually remove file */
		    if (killmode[2] && (handle[2]!=0)) {
			if (unlink(ffn2)) return -emsg(51);
		    }
		}

		/* process stream 2 */
		pointer2=(unsigned int *)(buffer2+sizeof(struct header_2));
		/* adjust to current epoch origin */
		t2=((unsigned long long)epoch2)<<32; 
		/* prepare decompression */
		idx2=0;readword2 = pointer2[idx2++]; /* raw buffer */
		resbits2=32; /* how much to eat */
		type2bitwidth=head2.timeorder; type2datawidth=head2.basebits;
		bitstoread2=type2bitwidth+type2datawidth; /* has to be <32 */
		tdiff_bitmask2 = (1<<type2bitwidth)-1; /* for unpacking */
		patternmask2 = (1<<type2datawidth)-1;
		emergency_break=
		    (realsize2-sizeof(struct header_2))/sizeof(unsigned int);
		ecnt2=0;/* count local events */

		/* prepare new stream 3 and 4 */
		open_epoch(epoch2);
		oldindex4=1; /* first entry connected to ecnt2 */
		
		accidentals=0;truecoincies=0;
		thisepoch_converted_entries=0;
		thisepoch_siftevents=0;
		thisepoch_testevents=0;

		epoch2++; /* prepare for next read */
	    }
	    /* extract one event */
	    if (resbits2>=bitstoread2) {
		tdiff2=(readword2>>(resbits2-bitstoread2));
		resbits2-=bitstoread2;
		if (!resbits2) {readword2=pointer2[idx2++];resbits2=32;}
	    } else {
		resbits2=bitstoread2-resbits2;
		tdiff2=readword2<<resbits2;
		readword2=pointer2[idx2++];
		resbits2=32-resbits2;
		tdiff2=(tdiff2 | (readword2>>resbits2));
	    }
	    pattern2= (tdiff2 & patternmask2);
	    tdiff2>>=type2datawidth;
	    /* we have a time difference word now in tdiff */
	    if (tdiff2 &= tdiff_bitmask2) { /* check for exception */
		/* test for end of stream */
		if (tdiff2==1) return -emsg(49); /* exit digest routine for this stream */
	    } else {
		/* read in complete difference */
		tdiff2=readword2<<(32-resbits2);
		readword2=pointer2[idx2++];
                /* catch shift 'feature' - normal */
		if (resbits2 & 0x1f) tdiff2 |= readword2>>resbits2;
		opatt2=pattern2;pattern2=tdiff2&patternmask2;
		tdiff2 >>=type2datawidth;
		tdiff2 |=  (opatt2<<(32-type2datawidth));
	    }
	    /* we now have a valid difference */
	    t2 +=tdiff2; ecnt2++;
	    gettwo=0;
	    continue;
	}
	/* do histogramming */
	if (histologname[0]) {
	    hdiff=eventdiff+DEFAULT_HISTODEPTH/2;
	    if (hdiff<DEFAULT_HISTODEPTH && hdiff>=0) 
		histo[histidx[((pointer1[ecnt1-1].dv & raw_patternmask) |
				(pattern2<<4))&255]][hdiff]++;
	}
	/* monitor accidentals at the upper edge of the track window */
	if (eventdiff>referencewindow1) accidentals++;
	/* coinicidence check */
	if ((eventdiff>-coincwindow) && (eventdiff<coincwindow)) { /* true */
	    truecoincies++;
	    /* get pattern 1 */
	    pattern1=pointer1[ecnt1-1].dv & raw_patternmask;
	    d=decisionmatrix[(pattern1 | (pattern2<<4))&  decisionindexmask];
	    /* printf("patt1: %d, patt2: %d, d:%d\n",pattern1,pattern2,d); */
	    if (d & keepthatpairmask) {
		if (d & testeventmask) { /* save as bell test event */
		    /* add to stream 5 */
		    stream5data = d & stream5datamask;
		    /* printf("stream5data: %x\n",stream5data); */
		    if (resbits5>=type5datawidth) {
			sendword5 |= (stream5data << (resbits5-type5datawidth));
			resbits5 = resbits5-type5datawidth;
			if (resbits5==0) { 
			    outbuf5[index5++]=sendword5;
			    sendword5=0;resbits5=32;
			}
		    } else {
			resbits5=type5datawidth-resbits5;
			sendword5 |= (stream5data >> resbits5);
			outbuf5[index5++]=sendword5;
			resbits5=32-resbits5;
			sendword5=stream5data << resbits5;
		    }
		    thisepoch_testevents++;
		} else { /* save as key event */
		    /* add to stream 3 */
		    stream3data = d & stream3datamask;
		    /* printf("stream3data: %x\n",stream3data); */
		    if (resbits3>=type3datawidth) {
			sendword3 |= (stream3data << (resbits3-type3datawidth));
			resbits3 = resbits3-type3datawidth;
			if (resbits3==0) { 
			    outbuf3[index3++]=sendword3;
			    sendword3=0;resbits3=32;
			}
		    } else {
			resbits3=type3datawidth-resbits3;
			sendword3 |= (stream3data >> resbits3);
			outbuf3[index3++]=sendword3;
			resbits3=32-resbits3;
			sendword3=stream3data << resbits3;
		    }
		}
		
		/* add to stream 4 */
		stream4data = ( d & stream4datamask)>>stream4datashift;
		/* printf("index: %i\n",ecnt2); */

		indexdiff4=ecnt2-oldindex4+2; /* index difference, corrected */
		oldindex4=ecnt2;
		
		/* long index diff exception */
		if (indexdiff4!=(t4=(indexdiff4 & idiff4_bitmask))) { 
		    /* first batch is codeword zero plus a few bits  */
		    t4a=indexdiff4 >> type4bitwidth;
		    /* save first part of this longer structure */
		    if (resbits4==32) {
			outbuf4[index4++]=t4a;
		    } else {
			sendword4 |= (t4a >> (32-resbits4));
			outbuf4[index4++]=sendword4;
			sendword4=t4a << resbits4;
		    }
		} 
		
		/* short word or rest of data, add state to shortword */
		t4a = (t4<<type4datawidth) | stream4data;
		/* save timing and transmit bits */
		if (resbits4>=bitstosend4) {
		    sendword4 |= (t4a << (resbits4-bitstosend4));
		    resbits4 = resbits4-bitstosend4;
		    if (resbits4==0) { 
			outbuf4[index4++]=sendword4;
			sendword4=0;resbits4=32;
		    }
		} else {
		    resbits4=bitstosend4-resbits4;
		    sendword4 |= (t4a >> resbits4);
		    outbuf4[index4++]=sendword4;
		    resbits4=32-resbits4;
		    sendword4=t4a << resbits4;
		}
		
		thisepoch_siftevents++;
	    }
	    thisepoch_converted_entries++;
	}
        /* do coincidence tracking  */
	if (servo_param && (eventdiff<trackwindow)) {
	    if (servo_param>0) {
		floattime +=eventdiff*servo_p1; /* event centered */
	    } else { /* time-based correction calculation */
		if (lastservotime) /* is initialized */
		    /* switch off servo if off for too long */
		    if ((servodiff=(long long int)(t1-lastservotime))<servoofftime)
			floattime +=((eventdiff*servodiff)<<1)
			    /servo_p1;
		lastservotime=t1;
	    }
	    timediff = timediff0-floattime/SERVO_GRANULARITY;
	    ft=floattime/SERVO_GRANULARITY;

	}	    
	/* prepare for new events */
	gettwo=1; getone=1;
    }
    
    /* return benignly */
    fprintf(stderr,"This is a benign end.\n");
    fprintf(debuglog,"benign end.\n");fflush(debuglog);

    
    /* evtl. close stream files */
    for (i=1;i<6;i++) 
	if (1== (typemode[i])) close(handle[i]); /* single file */
    
    for (i=0;i<5;i++) if (logfname[i][0]) fclose(loghandle[i]); /* logs */
    free(buffer1); free(buffer2); free(outbuf3); free(outbuf4); /* buffers */
    free(outbuf5);

    free(decisionmatrix);
    fclose(debuglog);
    return 0;
}
