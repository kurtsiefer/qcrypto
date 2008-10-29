/* ecd2.c:      Part of the quantum key distribution software for error
                correction and privacy amplification. Description
                see below. Version as of 20071228, works also for Ekert-91
                type protocols.

 Copyright (C) 2005-2007 Christian Kurtsiefer, National University
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

   Error correction demon. (modifications to original errcd see below).

   Runs in the background and performs a cascade
   error correction algorithm on a block of raw keys. Communication with a
   higher level controller is done via a command pipeline, and communication
   with the other side is done via packets which are sent and received via
   pipes in the filesystem. Some parameters (connection locations,
   destinations) are communicated via command line parameters, others are sent
   via the command interface. The program is capable to handle several blocks
   simultaneously, and to connect corresponding messages to the relevant
   blocks.
   The final error-corrected key is stored in a file named after the first
   epoch. If a block processing is requested on one side, it will fix the role
   to "Alice", and the remote side will be the "bob" which changes the bits
   accordingly. Definitions according to the flowchart in DSTA deliverable D3

usage:

  errcd -c commandpipe -s sendpipe -r receivepipe
        -d rawkeydirectory -f finalkeydirectory
	-l notificationpipe
	-q responsepipe -Q querypipe
	[ -e errormargin ]
	[ -E expectederror ]
	[ -k ]
	[ -J basicerror ]
	[ -T errorbehaviour ]
	[ -V verbosity ]
	[ -I ]
	[ -i ]
	[ -p ]
	[ -B BER | -b rounds ]

options/parameters:

 DIRECTORY / CONNECTION PARAMETERS:

  -c commandpipe:       pipe for receiving commands. A command is typically an
                        epoch name and a number of blocks to follow, separated
			by a whitespace. An optional error argument can be
			passed as a third parameter. Commands are read via
			fscanf, and should be terminated with a newline.
  -s sendpipe:          binary connection which reaches to the transfer
                        program. This is for packets to be sent out to the
			other side. Could be replaced by sockets later.
  -r receivepipe:       same as sendpipe, but for incoming packets.
  -d rawkeydirectory:   directory which contains epoch files for raw keys in
                        stream-3 format
  -f finalkeydirectory: Directory which contains the final key files.
  -l notificationpipe:  whenever a final key block is processed, its epoch name
                        is written into this pipe or file. The content of the
			message is determined by the verbosity flag.
  -Q querypipe:         to request the current status of a particular epoch
                        block, requests may be sent into this pipe. Syntax TBD.
  -q respondpipe:       Answers to requests will be written into this pipe or
                        file.

 CONTROL OPTIONS:
 
  -e errormargin:       A float parameter for how many standard deviations
                        of the detected errors should be added to the
			information leakage estimation to eve, assuming a
			poissonian statistics on the found errors (i.e.,
			if 100 error bits are found, one standard deviation
			in the error rate QBER is QBER /Sqrt(10). )
			Default is set to 0.
  -E expectederror:     an initial error rate can be given for choosing the
                        length of the first test. Default is 0.05. This may
			be overridden by a servoed quantity or by an explicit
			statement in a command.
  -k                    killfile option. If set, the raw key files will be
                        deleted after writing the final key into a file.
  -J basicerror:        Error rate which is assumed to be generated outside the
                        influence of an eavesdropper.
  -T errorbehavior:     Determines the way how to react on errors which should
                        not stop the demon. Default is 0. detailed behavior:
			0: terminate program on everything
			1: ignore errors on wrong packets???
			2: ignore errors inherited from other side
  -V verbosity:         Defines verbosity mode on the logging output after a
                        block has been processed. options:
			0: just output the raw block name (epoch number in hex)
			1: output the block name, number of final bits
			2: output block name, num of initial bits, number of
			   final bits, error rate
			3: same as 2, but in plain text
			4: same as 2, but with explicit number of leaked bits
			   in the error correction procedure
			5: same as 4, but with plain text comments
  -I                    ignoreerroroption. If this option is on, the initial
                        error measurement for block optimization is skipped, 
			and the default value or supplied value is chosen. This
			option should increase the efficiency of the key
			regeneration if a servo for the error rate is on.
  -i                    deviceindependent option. If this option is set,
                        the deamon expects to receive a value for the Bell
			violation parameter to estimate the knowledge of an 
			eavesdropper.
  -p                    avoid privacy amplification. For debugging purposes, to
                        find the residual error rate
  -B BER:               choose the number of BICONF rounds to meet a final
                        bit error probability of BER. This assumes a residual
			error rate of 10^-4 after the first two rounds.
  -b rounds:            choose the number of BICONF rounds. Defaults to 10,
                        corresponding to a BER of 10^-7.


History: first specs 17.9.05chk

status 01.4.06 21:37; runs through and leaves no errors in final key. 
       1.5.06 23:20: removed biconf indexing bugs & leakage errors
       2.5.06 10:14  fixed readin problem with word-aligned lengths
       3.5.06 19:00 does not hang over 300 calls
       28.10.06     fixed sscanf to read in epochs >0x7fffffff
       14.07.07     logging leaked bits, verbosity options 4+5
       9.-18.10.07      fixed Bell value transmission for other side
       24.10.08         fixed error estimation for BB84


       introduce rawbuf variable to clean buffer in keyblock struct (status?)

modified version of errcd to take care of the followig problems:
   - initial key permutation
   - more efficient biconf check
   - allow recursive correction after biconf error discoveries 
    status: seems to work. needs some cleanup, and needs to be tested for
      longer key lenghts to confirm the BER below 10^-7 with some confidence.
      (chk 21.7.07)  
      - inserted error margin option to allow for a few std deviations of the
      detected error

open questions / issues:
   check assignment of short indices for bit length....
   check consistency of processing status
   get a good RNG source or recycle some bits from the sequence....currently
     it uses urandom as a seed source.
   The pseudorandom generator in this program is a Gold sequence and possibly
     dangerous due to short-length correlations - perhaps something better?
   should have more consistency tests on packets
   still very chatty on debug information
   query/response mechanism not implemented yet

*/


#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <math.h>

/* definitions of packet headers */
#include "errcorrect.h" 
#include "rnd.h"


/* #define SYSTPERMUTATION */  /* for systematic rather than rand permut */

/* #define mallocdebug */

/* debugging */
int mcall=0, fcall=0;
char *malloc2(unsigned int s) {
    char *p;
#ifdef mallocdebug
    printf("process %d malloc call no. %d for %d bytes...",getpid(),mcall,s);
#endif
    mcall++;
    p=malloc(s);
#ifdef mallocdebug
   printf("returned: %p\n",p);
#endif
    return p;
}
void free2(void *p){
#ifdef mallocdebug
    printf("process %d free call no. %d for %p\n",getpid(),fcall,p);
#endif
    fcall++;
    free(p);
    return;
}

/* typical file names */
#define RANDOMGENERATOR "/dev/urandom" /* this does not block but is BAD....*/

/* type declaration for stream-3 raw key files; should come from extra h file */
typedef struct header_3 {/* header for type-3 stream packet */
    int tag;
    unsigned int epoc;
    unsigned int length;
    int bitsperentry; 
} h3;

#define TYPE_3_TAG 3
#define TYPE_3_TAG_U 0x103
/* type declaration for stream-7 final key file */

typedef struct header_7 {/* header for type-7 stream packet */
    int tag;
    unsigned int epoc;
    unsigned int numberofepochs;
    int numberofbits; 
} h7;
#define TYPE_7_TAG 7
#define TYPE_7_TAG_U 0x107
   

/* -------------------------------------------------------------------- */
/* definition of a structure containing all informations about a block */
typedef struct keyblock {
    unsigned int startepoch; /* initial epoch of block */
    unsigned int numberofepochs;
    unsigned int *rawmem; /* buffer root for freeing block afterwards */
    unsigned int *mainbuf; /* points to main buffer for key */
    unsigned int *permutebuf; /* keeps permuted bits */
    unsigned int *testmarker; /* marks tested bits */
    unsigned short int *permuteindex; /* keeps permutation */
    unsigned short int *reverseindex; /* reverse permutation */
    int role; /* defines which role to take on a block: 0: Alice, 1: Bob */
    int initialbits; /* bits to start with */
    int leakagebits; /* information which has gone public */
    int processingstate; /* determines processing status  current block.
			    See defines below for interpretation */
    int initialerror;  /* in multiples of 2^-16 */
    int errormode;     /* determines if error estimation has to be done */
    int estimatederror; /* number of estimated error bits */
    int estimatedsamplesize; /* sample size for error  estimation  */
    int finalerrors; /* number of discovered errors */
    int RNG_usage; /* defines mode of randomness. 0: PRNG, 1: good stuff */
    unsigned int RNG_state; /* keeps the state of the PRNG for this thread */
    int k0, k1; /* binary block search lengths */
    int workbits; /* bits to work with for BICONF/parity check */
    int partitions0, partitions1; /* number of partitions of k0,k1 length */
    unsigned int *lp0, *lp1; /* pointer to local parity info 0 / 1 */
    unsigned int *rp0, *rp1; /* pointer to remote parity info 0 / 1 */
    unsigned int *pd0, *pd1; /* pointer to parity difference fileld */
    int diffnumber;  /* number of different blocks in current round */
    int diffnumber_max; /* number of malloced entries for diff indices */
    unsigned int *diffidx; /* pointer to a list of parity mismatch blocks */
    unsigned int *diffidxe; /* end of interval */
    int binsearch_depth; /* encodes state of the scan. Starts with 0,
			    and contains the pass (0/1) in the MSB */
    int biconf_round; /* contains the biconf round number, starting with 0 */
    int biconflength; /* current length of a biconf check range */
    int correctederrors; /* number of corrected bits */
    int finalkeybits; /* how much is left */
    float BellValue; /* for Ekert-type protocols */
    
} kblock;
/* definition of the processing state */
#define PRS_JUSTLOADED 0  /* no processing yet (passive role) */
#define PRS_NEGOTIATEROLE 1 /* in role negotiation with other side */
#define PRS_WAITRESPONSE1 2 /* waiting for error est response from bob */
#define PRS_GETMOREEST 3  /* waiting for more error est bits from Alice */
#define PRS_KNOWMYERROR 4 /* know my error estimation */
#define PRS_PERFORMEDPARITY1 5 /* know my error estimation */
#define PRS_DOING_BICONF 6 /* last biconf round */


/* -------------------------------------------------------------------- */
/* structure to hold list of blocks. This helps dispatching packets? */
typedef struct blockpointer {
    unsigned int epoch;
    struct keyblock *content;  /* the gory details */
    struct blockpointer *next;  /* next in chain; if NULL then end */
    struct blockpointer *previous; /* previous block */
} erc_bp__;
struct blockpointer *blocklist=NULL;

/* forward decl */
void dumpmsg(struct keyblock *kb, char *msg);


/* -------------------------------------------------------------------- */
/* structure which holds packets to send */
typedef struct packet_to_send {
    int length; /* in bytes */
    char *packet; /* pointer to content */
    struct packet_to_send *next; /* next one to send */
} pkt_s;
struct packet_to_send *next_packet_to_send=NULL;
struct packet_to_send *last_packet_to_send=NULL;
/* -------------------------------------------------------------------- */
/* structure to hold received messages */
typedef struct packet_received {
    int length; /* in bytes */
    char *packet; /* pointer to content */
    struct packet_received *next; /* next in chain */
} pack_r;
/* head node pointing to a simply joined list of entries */
struct packet_received *rec_packetlist=NULL;


/* error handling */
char *errormessage[] = {
  "No error.",
  "Error reading in verbosity argument.", /* 1 */
  "Error reading name for command pipe.",
  "Error reading name for sendpipe.",
  "Error reading name for receive pipe.",
  "Error reading directory name for raw key.", /* 5 */
  "Error reading directory name for final key.",
  "Error reading name for notify pipe.",
  "Error reading name for query pipe.",
  "Error reading name for response-to-query pipe.",
  "Error parsing error threshold.", /* 10 */
  "Error threshold out of range (0.01...0.3)",
  "Error parsing initial error level",
  "Initial error level out of range (0.01...0.3)",
  "Error parsing intrinsic error level",
  "Intrinsic error level out of range (0...0.05)", /* 15 */
  "Error parsing runtime behavior (range must be 0..?)",
  "One of the pipelines of directories is not specified.",
  "Cannot stat or open command handle",
  "command handle is not a pipe", 
  "Cannot stat/open send pipe", /* 20 */
  "send pipe is not a pipe",
  "Cannot stat/open receive pipe",
  "receive pipe is not a pipe",
  "Cannot open notify target",
  "Cannot stat/open query input pipe", /* 25 */
  "query intput channel is not a pipe",
  "Cannot open query response pipe",
  "select call failed in main loop",
  "error writing to target pipe",
  "command set to short",  /* 30 */
  "estimated error out of range",
  "wrong number of epochs specified.",
  "overlap with existing epochs",
  "error creating new thread",
  "error initiating error estimation", /* 35 */
  "error reading message",
  "cannot malloc message buffer",
  "cannot malloc message buffer header",
  "cannot open random number generator",
  "cannot get enough random numbers", /* 40 */
  "initial error out of useful bound",
  "not enough bits for initial testing",
  "cannot malloc send buffer pointer",
  "received wrong packet type",
  "received unrecognized message subtype", /* 45 */
  "epoch overlap error on bob side",
  "error reading in epochs in a thread on bob side",
  "cannot get thread for message 0",
  "cannot find thread in list",
  "cannot find thread for message 2", /* 50 */
  "received invalid seed.",
  "inconsistent test-bit number received",
  "can't malloc parity buffer",
  "cannot malloc difference index buffer",
  "cannot malloc binarysearch message buf", /* 55 */
  "illegal role in binsearch",
  "don't know index encoding", 
  "cannot malloc binarysearch message II buf", 
  "illegal pass argument",
  "cannot malloc BCONF request message", /* 60 */
  "cannot malloc BICONF response message",
  "cannot malloc privamp message",
  "cannot malloc final key structure",
  "cannot open final key target file",
  "write error in fnal key",  /* 65 */
  "cannot remove raw key file",
  "cannot open raw key file",
  "cannot read rawkey header",
  "incorrect epoch in rawkey",
  "wrong bitnumber in rawkey (must be 1)", /* 70 */
  "bitcount too large in rawkey",
  "could not read enough bytes from rawkey", 
  "in errorest1: cannot get thread",
  "wrong pass index",
  "cmd input buffer overflow", /* 75 */
  "cannot parse biconf round argument",
  "biconf round number exceeds bounds of 1...100",
  "cannot parse final BER argument",
  "BER argument out of range",

};

int emsg(int code) {
  fprintf(stderr,"%s\n",errormessage[code]);
  return code;
};


/* default definitions */
#define FNAMELENGTH 200  /* length of file name buffers */
#define FNAMFORMAT "%200s"   /* for sscanf of filenames */
#define DEFAULT_ERR_MARGIN 0. /* eavesdropper is assumed to have full
				     knowledge on raw key */
#define MIN_ERR_MARGIN 0. /* for checking error margin entries */
#define MAX_ERR_MARGIN 100. /* for checking error margin entries */
#define DEFAULT_INIERR 0.075 /* initial error rate */
#define MIN_INI_ERR 0.005 /* for checking entries */
#define MAX_INI_ERR 0.14 /* for checking entries */
#define USELESS_ERRORBOUND 0.15 /* for estimating the number of test bits */
#define DESIRED_K0_ERROR 0.18 /* relative error on k */
#define INI_EST_SIGMA 2. /* stddev on k0 for initial estimation */
#define DEFAULT_KILLMODE 0 /* no raw key files are removed by default */
#define DEFAULT_INTRINSIC 0 /* all errors are due to eve */
#define MAX_INTRINSIC 0.05 /* just a safe margin */
#define DEFAULT_RUNTIMEERRORMODE 0 /* all error s stop daemon */
#define MAXRUNTIMEERROR 2 
#define FIFOINMODE O_RDWR | O_NONBLOCK
#define FIFOOUTMODE O_RDWR
#define FILEINMODE O_RDONLY
#define FILEOUTMODE O_WRONLY | O_CREAT | O_TRUNC
#define OUTPERMISSIONS 0600
#define TEMPARRAYSIZE (1<<11) /* to capture 64 kbit of raw key */
#define MAXBITSPERTHREAD (1<<16) 
#define DEFAULT_VERBOSITY 0
#define DEFAULT_BICONF_LENGTH 256 /* length of a final check */
#define DEFAULT_BICONF_ROUNDS 10 /* number of BICONF rounds */
#define MAX_BICONF_ROUNDS 100 /* enough for BER < 10^-27 */
#define AVG_BINSEARCH_ERR 0.0032 /* what I have seen at some point for 10k 
                                    this goes with the inverse of the length
				    for block lengths between 5k-40k */
#define DEFAULT_ERR_SKIPMODE 0 /* initial error estimation is done */
#define CMD_INBUFLEN 200

/* helpers */
#define MAX(A,B) ((A) > (B)? (A) : (B) )
#define MIN(A,B) ((A) > (B)? (B) : (A) )

/* helper to obtain the smallest power of two to carry a number a */
int get_order(int a) {
    unsigned int order = 0xffffffff;
    while ((order & a)==a) order >>=1;
    return (order<<1)+1;
}
/* get the number of bits necessary to carry a number x ; result is e.g.
   3 for parameter 8, 5 for parameter 17 etc. */
int get_order_2(int x) {
    int x2; int retval=0;
    for(x2=x-1;x2;x2>>=1) retval++;
    return retval;
}

/* helper for mask for a given index i on the longint array */
__inline__ unsigned int bt_mask(int i) {
    return 1<<(31-(i&31));
}

/* helper to insert a send packet in the sendpacket queue. Parameters are
   a pointer to the structure and its length. Return value is 0 on success
   or !=0 on malloc failure */
int pidx=0;
int insert_sendpacket(char *message, int length) {
    struct packet_to_send *newpacket, *lp;
    pidx++;
    newpacket = (struct packet_to_send *)malloc2(sizeof(struct packet_to_send));
    if (!newpacket) return 43;

    newpacket->length = length;
    newpacket->packet = message;  /* content */
    newpacket->next = NULL;

    lp=last_packet_to_send;
    if (lp) lp->next = newpacket; /* insetr in chain */
    last_packet_to_send = newpacket;
    if (!next_packet_to_send) next_packet_to_send=newpacket;

    /* for debug: send message, take identity from first available slot */
    /*dumpmsg(blocklist->content, message); */

    return 0; /* success */
}

/* global parameters and variables */
char fname[8][FNAMELENGTH]={"","","","","","","",""}; /* filenames */
int handle[8]; /* handles for files accessed by raw I/O */
FILE* fhandle[8]; /* handles for files accessed by buffered I/O */
float errormargin=DEFAULT_ERR_MARGIN;
float initialerr=DEFAULT_INIERR;  /* What error to assume initially */
int killmode=DEFAULT_KILLMODE; /* decides on removal of raw key files */
float intrinsicerr=DEFAULT_INTRINSIC; /* error rate not under control of eve */
int runtimeerrormode=DEFAULT_RUNTIMEERRORMODE;
int verbosity_level=DEFAULT_VERBOSITY;
int biconf_length = DEFAULT_BICONF_LENGTH; /* how long is a biconf */
int biconf_rounds = DEFAULT_BICONF_ROUNDS; /* how many times */
int ini_err_skipmode = DEFAULT_ERR_SKIPMODE; /* 1 if error est to be skipped */
int disable_privacyamplification = 0; /* off normally, != 0 for debugging */
int bellmode = 0; /* 0: use estimated error, 1: use supplied bell value */

/* ------------------------------------------------------------------------- */
/* code to check if a requested bunch of epochs already exists in the thread
   list. Uses the start epoch and an epoch number as arguments; returns 0 if
   the requested epochs are not used yet, otherwise 1. */
int check_epochoverlap(unsigned int epoch, int num) {
    struct blockpointer *bp = blocklist;
    unsigned int se;
    int en;
    while (bp) { /* as long as there are more blocks to test */
	se=bp->content->startepoch;en=bp->content->numberofepochs;
	if (MAX(se,epoch)<=(MIN(se+en,epoch+num)-1)) {
	    return 1; /* overlap!! */
	}
	bp=bp->next;
    }
    /* did not find any overlapping epoch */
    return 0;
}
/* helper for name. adds a slash, hex file name and a terminal 0 */
char hexdigits[]="0123456789abcdef";
void atohex(char* target,unsigned int v) {
    int i;
    target[0]='/';
    for (i=1;i<9;i++) target[i]=hexdigits[(v>>(32-i*4)) & 15];
    target[9]=0;
}
/* ------------------------------------------------------------------------- */
/* code to prepare a new thread from a series of raw key files. Takes epoch,
   number of epochs and an initially estimated error as parameters. Returns
   0 on success, and 1 if an error occurred (maybe later: errorcode) */
int create_thread(unsigned int epoch, int num, float inierr, float BellValue) {
    static unsigned int temparray[TEMPARRAYSIZE];
    static struct header_3 h3; /* header for raw key file */
    unsigned int residue, residue2,tmp; /* leftover bits at end */
    int resbitnumber; /* number of bits in the residue */
    int newindex; /* points to the next free word */
    unsigned int epi; /* epoch index */
    unsigned int enu;
    int retval,i,bitcount;
    char ffnam[FNAMELENGTH+10]; /* to store filename */
    struct blockpointer*bp; /* to hold new thread */
    int getbytes; /* how much memory to ask for */
    unsigned int *rawmem; /* to store raw key */
    
    /* read in file by file in temporary array */
    newindex=0;resbitnumber=0;residue=0;bitcount=0;
    for (enu=0;enu<num;enu++) {
	epi=epoch+enu; /* current epoch index */
	strncpy(ffnam, fname[3], FNAMELENGTH);
	atohex(&ffnam[strlen(ffnam)],epi);
	handle[3]=open(ffnam,FILEINMODE); /* in blocking mode */
	if(-1==handle[3]) {
	    fprintf(stderr,"cannot open file >%s< errno: %d\n",ffnam,errno);
	    return 67; /* error opening file */
	}
	/* read in file 3 header */
	if (sizeof(h3)!=(i=read(handle[3],&h3,sizeof(h3)))) {
	    fprintf(stderr,"error in read: return val:%d errno: %d\n",i,errno);    
	    return 68;
	}
	if (h3.epoc !=epi) {
	    fprintf(stderr,"incorrect epoch; want: %08x have: %08x\n",
		    epi,h3.epoc);	    	    
	    return 69; /* not correct epoch */
	}
	
	if (h3.bitsperentry !=1 )  return 70; /* not a BB84 raw key */
	if (bitcount+h3.length>=MAXBITSPERTHREAD)
	    return 71;  /* not enough space */
	
	i=(h3.length/32)+((h3.length&0x1f)?1:0); /* number of words to read */
	retval=	read(handle[3],&temparray[newindex],i*sizeof(unsigned int));
	if (retval!=i*sizeof(unsigned int)) return 72; /* not enough read */
    
	/* close and possibly remove file */
	close(handle[3]);
	if (killmode) {retval = unlink(ffnam); if (retval) return 66;}

	/* residue update */
	tmp=temparray[newindex+i-1] & ((~1)<<(31-(h3.length & 0x1f)));
	residue |= (tmp >> resbitnumber);
	residue2 = tmp << (32-resbitnumber);
	resbitnumber +=(h3.length&0x1f);
	if ( h3.length & 0x1f ) { /* we have some residual bits */
	    newindex += (i-1);
	} else { /* no fresh residue, old one stays as is */
	    newindex += i; 
	}
	if (resbitnumber >31) {/* write one in buffer */
	    temparray[newindex]=residue; /* store residue */
	    newindex +=1;
	    residue=residue2; /* new residue */
	    resbitnumber-=32;
	}
	bitcount+=h3.length;
    }

    /* finish up residue */
    if (resbitnumber>0) {
	temparray[newindex]=residue; /* msb aligned */
	newindex++;
    } /* now newindex contains the number of words for this key */

    /* create thread structure */
    bp = (struct blockpointer *)malloc2(sizeof(struct blockpointer));
    if (!bp) return 34; /* malloc failed */
    bp->content=(struct keyblock *)malloc2(sizeof(struct keyblock));
    if (!(bp->content)) return 34; /* malloc failed */
    /* zero all otherwise unset keyblock entries */
    bzero(bp->content,sizeof(struct keyblock));
    /* how much memory is needed ?
       raw key, permuted key, test selection, two permutation indices */
    getbytes=newindex*3*sizeof(unsigned int)
	+bitcount*2*sizeof(unsigned short int);
    rawmem=(unsigned int *) malloc2(getbytes);
    if (!rawmem) return 34; /* malloc failed */
    bp->content->rawmem = rawmem ; /* for later free statement */
    bp->content->startepoch=epoch;
    bp->content->numberofepochs=num;
    bp->content->mainbuf=rawmem; /* main key; keep this in mind for free */
    bp->content->permutebuf=&bp->content->mainbuf[newindex];
    bp->content->testmarker=&bp->content->permutebuf[newindex];
    bp->content->permuteindex=
	(unsigned short int *)&bp->content->testmarker[newindex];
    bp->content->reverseindex=
	(unsigned short int *)&bp->content->permuteindex[bitcount];
    /* copy raw key into thread and clear testbits, permutebits */
    for (i=0;i<newindex;i++) {
	bp->content->mainbuf[i]=temparray[i];
	bp->content->permutebuf[i]=0;
	bp->content->testmarker[i]=0;
    }
    bp->content->initialbits=bitcount; /* number of bits in stream */
    bp->content->leakagebits=0; /* start with no initially lost bits */
    bp->content->processingstate=PRS_JUSTLOADED; /* just read in */
    bp->content->initialerror=(int)(inierr*(1<<16));
    bp->content->BellValue=BellValue;
    /* insert thread in thread list */
    bp->epoch=epoch;
    bp->previous=NULL;bp->next=blocklist;
    if (blocklist) blocklist->previous = bp; /* update existing first entry */
    blocklist=bp;  /* update blocklist */
    return 0;
}

/* ------------------------------------------------------------------------- */
/* function to obtain the pointer to the thread for a given epoch index.
   Argument is epoch, return value is pointer to a struct keyblock or NULL
   if none found. */
struct keyblock *get_thread(unsigned int epoch) {
    struct blockpointer *bp = blocklist;
    while (bp) {
	if (bp->epoch==epoch) return bp->content;
	bp=bp->next;
    }
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* function to remove a thread out of the list. parameter is the epoch index,
   return value is 0 for success and 1 on error. This function is called if
   there is no hope for error recovery or for a finished thread. */
int remove_thread(unsigned int epoch) {
    struct blockpointer *bp = blocklist;
    while (bp) {
	if (bp->epoch==epoch) break;
	bp=bp->next;
    }
    if (!bp) return 49; /* no block there */
    /* remove all internal structures */
    free2(bp->content->rawmem); /* bit buffers, changed to rawmem 11.6.06chk */
    if (bp->content->lp0) free (bp->content->lp0); /* parity storage */
    if (bp->content->diffidx) free2(bp->content->diffidx);
    free2(bp->content); /* main thread frame */
    
    /* unlink thread out of list */
    if (bp->previous) {
	bp->previous->next = bp->next;
    } else {
	blocklist = bp->next;
    }
    if (bp->next) bp->next->previous = bp->previous;

    printf("removed thread %08x, new blocklist: %p \n",epoch, blocklist);
    fflush(stdout);
    /* remove thread list entry */
    free2(bp);
    return 0;
}
/* ------------------------------------------------------------------------- */
/* helper function to prepare a message containing a given sample of bits.
   parameters are a pointer to the thread, the number of bits needed and an
   errorormode (0 for normal error est, err*2^16 forskip ). returns a pointer
   to the message or NULL on error. 
   Modified to tell the other side about the Bell value for privacy amp in
   the device indep mode 
*/
struct ERRC_ERRDET_0 *fillsamplemessage(struct keyblock *kb,
					int bitsneeded, int errormode,
					float BellValue) {
    int msgsize; /* keeps size of message */
    struct  ERRC_ERRDET_0 *msg1; /* for header to be sent */
    unsigned int *msg1_data; /* pointer to data array */
    int i,bipo,rn_order; /* counting index, bit position */
    unsigned int localdata, bpm; /* for bit extraction */

    /* prepare a structure to be sent out to the other side */
    /* first: get buffer.... */
    msgsize= sizeof(struct  ERRC_ERRDET_0)+ 4*((bitsneeded+31)/32);
    msg1 = (struct  ERRC_ERRDET_0 *) malloc2(msgsize);
    if (!msg1) return NULL; /* cannot malloc */
    /* ...extract pointer to data structure... */
    msg1_data = (unsigned int *)&msg1[1];
    /* ..fill header.... */
    msg1->tag = ERRC_PROTO_tag; msg1->bytelength = msgsize;
    msg1->subtype = ERRC_ERRDET_0_subtype; msg1->epoch = kb->startepoch;
    msg1->number_of_epochs = kb->numberofepochs;
    msg1->seed = kb->RNG_state; /* this is the seed */
    msg1->numberofbits = bitsneeded;
    msg1->errormode = errormode;
    msg1->BellValue = BellValue;

   /* determine random number order needed for given bitlength */
    /* can this go into the keyblock preparation ??? */
    rn_order = get_order_2(kb->initialbits);
    /* mark selected bits in this stream and fill this structure with bits */
    localdata = 0; /* storage for bits */
    for (i=0;i<bitsneeded;i++) { /* count through all needed bits */
	do { /* generate a bit position */
	    bipo = PRNG_value2(rn_order,&kb->RNG_state);
	    if (bipo > kb->initialbits) continue; /* out of range */
	    bpm = bt_mask(bipo); /* bit mask */
	    if (kb->testmarker[bipo/32] & bpm) continue; /* already used */
	    /* got finally a bit */
	    kb->testmarker[bipo/32] |= bpm; /* mark as used */
	    if (kb->mainbuf[bipo/32] & bpm) localdata |= bt_mask(i); 
	    if ((i&31)==31) {
		msg1_data[i/32]=localdata;
		localdata=0; /* reset buffer */
	    }
	    break; /* end rng search cycle */
	} while (1);
    }


    /* fill in last localdata */
    if (i&31) { msg1_data[i/32]=localdata; } /* there was something left */

    /* update thread structure with used bits */
    kb->leakagebits += bitsneeded;
    kb->processingstate = PRS_WAITRESPONSE1;

    return msg1; /* pointer to message */
}

/* ------------------------------------------------------------------------- */
/* helper function to get a seed from the random device; returns seed or 0 
   on error */
unsigned int get_r_seed(void) {
    int rndhandle; /* keep device handle for random device */
    unsigned int reply;
    
    rndhandle=open(RANDOMGENERATOR,O_RDONLY);
    if (-1==rndhandle) {fprintf(stderr,"errno: %d",errno); return 39; }
    if (sizeof(unsigned int)!=read(rndhandle,&reply,sizeof(unsigned int))) {
	return 0; /* not enough */ }
    close(rndhandle);
    return reply;
}

/* ------------------------------------------------------------------------ */
/* function to provide the number of bits needed in the initial error
   estimation; eats the local error (estimated or guessed) as a float. Uses
   the maximum for either estimating the range for k0 with the desired error,
   or a sufficient separation from the no-error-left area. IS that fair?
   Anyway, returns a number of bits. */
int testbits_needed(float e) {
    float ldi;
    int bn;
    ldi=USELESS_ERRORBOUND-e; /* difference to useless bound */
    bn=MAX((int)(e*INI_EST_SIGMA/ldi/ldi+.99),
	   (int)(1./e/DESIRED_K0_ERROR/DESIRED_K0_ERROR));
    return bn;
}

/* ------------------------------------------------------------------------- */
/* function to initiate the error estimation procedure. parameter is 
   statrepoch, return value is 0 on success or !=0 (w error encoding) on error.
 */
int errorest_1(unsigned int epoch) {
    struct keyblock *kb; /* points to current keyblock */
    float f_inierr, f_di; /* for error estimation */
    int bits_needed; /* number of bits needed to send */
    struct  ERRC_ERRDET_0 *msg1; /* for header to be sent */
    
    if (!(kb=get_thread(epoch))) return 73; /* cannot find key block */
    

    /* set role in block to alice (initiating the seed) in keybloc struct */
    kb->role = 0;
    /* seed the rng, (the state has to be kept with the thread, use a lock
       system for the rng in case several ) */
    kb->RNG_usage = 0; /* use simple RNG */
    if (!(kb->RNG_state = get_r_seed())) return 39; 
   
    /*  evaluate how many bits are needed in this round */
    f_inierr=kb->initialerror/65536.; /* float version */
    
    if (ini_err_skipmode) { /* don't do error estimation */
	kb->errormode = 1;
	msg1 = fillsamplemessage(kb, 1,kb->initialerror,kb->BellValue);
    } else {
	kb->errormode = 0;
	f_di = USELESS_ERRORBOUND-f_inierr;
	if (f_di <= 0) return 41; /* no error extractable */
	bits_needed = testbits_needed(f_inierr);
	
	if (bits_needed >=kb->initialbits) return 42; /* not possible */
	/* fill message with sample bits */
	msg1 = fillsamplemessage(kb, bits_needed,0,kb->BellValue);
    }
    if (!msg1) return 43; /* a malloc error occured */

    /* send this structure to the other side */
    insert_sendpacket((char *)msg1, msg1->bytelength);

    /* go dormant again.  */
    return 0;    
}

/* ------------------------------------------------------------------------- */
/* function to process the first error estimation packet. Argument is a pointer
   to the receivebuffer with both the header and the data section. Initiates
   the error estimation, and prepares the next  package for transmission.
   Currently, it assumes only PRNG-based bit selections.

   Return value is 0 on success, or an error message useful for emsg.

*/
int process_esti_message_0(char *receivebuf) {
    struct  ERRC_ERRDET_0 *in_head; /* holds header */
    struct keyblock *kb; /* poits to thread info */
    unsigned int *in_data; /* holds input data bits */
    /* int retval; */
    int i, seen_errors,rn_order, bipo;
    unsigned int bpm;
    struct ERRC_ERRDET_2 *h2; /* for more requests */
    struct ERRC_ERRDET_3 *h3; /* reply message */
    int replymode; /* 0: terminate, 1: more bits, 2: continue */
    float localerror, ldi;
    int newbitsneeded = 0; /* to keep compiler happy */
    int overlapreply;
    
    /* get convenient pointers */
    in_head = (struct  ERRC_ERRDET_0 *)receivebuf;
    in_data = (unsigned int *)(&receivebuf[sizeof(struct  ERRC_ERRDET_0)]);

    /* try to find overlap with existing files */
    overlapreply=check_epochoverlap(in_head->epoch, in_head->number_of_epochs);
    
    if (overlapreply && in_head->seed) return 46; /* conflict */
    if ((!overlapreply) && !(in_head->seed)) return 51;
    
    if (overlapreply) { /* we have an update message to request more bits */
	kb=get_thread(in_head->epoch);
	if (!kb) return 48; /* cannot find thread */
	kb->leakagebits += in_head->numberofbits;
	kb->estimatedsamplesize +=in_head->numberofbits;
	seen_errors = kb->estimatederror;
    } else {

	/* create a thread with the loaded files, get thead handle */
	if ((i=create_thread(in_head->epoch, in_head->number_of_epochs,0.0,0.0)))
	{ fprintf(stderr,"create_thread return code: %d epoch: %08x, number:%d\n",i,in_head->epoch, in_head->number_of_epochs);
	    return 47; /* no success */
	}

	kb = get_thread(in_head->epoch);
	if (!kb) return 48; /* should not happen */

	/* update the thread with the type status, and with the info form the
	   other side */
	kb->RNG_state = in_head->seed;
	kb->RNG_usage = 0; /* use PRNG sequence */
	kb->leakagebits = in_head->numberofbits;
	kb->role = 1; /* being bob */
	seen_errors=0;
	kb->estimatedsamplesize=in_head->numberofbits;
	kb->BellValue = in_head->BellValue;
    }
    
    /* do the error estimation */
    rn_order=get_order_2(kb->initialbits);
    
    for (i=0;i<(in_head->numberofbits);i++) {
	do { /* generate a bit position */
	    bipo = PRNG_value2(rn_order,&kb->RNG_state);
	    if (bipo > kb->initialbits) continue; /* out of range */
	    bpm = bt_mask(bipo); /* bit mask */
	    if (kb->testmarker[bipo/32] & bpm) continue; /* already used */
	    /* got finally a bit */
	    kb->testmarker[bipo/32] |= bpm; /* mark as used */
	    if (((kb->mainbuf[bipo/32] & bpm)?1:0) ^ 
		((in_data[i/32] & bt_mask(i))?1:0)) { /* error */
		seen_errors++;
	    }
	    break;
	} while (1);
    }

    /* save error status */
    kb->estimatederror = seen_errors;

    if (in_head->errormode) { /* skip the error estimation */
	kb->errormode = 1;
	localerror = (float)in_head->errormode /65536.0;
	replymode = 2; /* skip error est part */
    } else {
	kb->errormode = 0;
	/* make decision if to ask for more bits */
	localerror=(float)seen_errors/(float)(kb->estimatedsamplesize);
	
	ldi=USELESS_ERRORBOUND-localerror;
	if (ldi <= 0.) { /* ignore key bits : send error number to terminate */
	    replymode = 0;
	} else {
	    newbitsneeded = testbits_needed(localerror);
	    if (newbitsneeded > kb->initialbits) { /* will never work */
		replymode = 0;
	    } else {
		if (newbitsneeded > kb->estimatedsamplesize) { /*  more bits */
		    replymode = 1;
		} else {   /* send confirmation message */
		    replymode = 2;
		}
	    }
	}
    }

    /* prepare reply message */
    switch (replymode ) {
	case 0: case 2: /* send message 3 */
	    h3 = (struct ERRC_ERRDET_3 *)malloc2(sizeof(struct ERRC_ERRDET_3));
	    if (!h3) return 43; /* cannot malloc */
	    h3->tag = ERRC_PROTO_tag; h3->subtype = ERRC_ERRDET_3_subtype;
	    h3->bytelength = sizeof(struct ERRC_ERRDET_3);
	    h3->epoch = kb->startepoch;
	    h3->number_of_epochs = kb->numberofepochs;
	    h3->tested_bits = kb->leakagebits;
	    h3->number_of_errors = seen_errors;
	    insert_sendpacket((char *)h3, h3->bytelength); /* error trap? */
	    break;
	case 1: /* send message 2 */
	    h2 = (struct ERRC_ERRDET_2 *)malloc2(sizeof(struct ERRC_ERRDET_2));
	    h2->tag = ERRC_PROTO_tag; h2->subtype = ERRC_ERRDET_2_subtype;
	    h2->bytelength = sizeof(struct ERRC_ERRDET_2);
 	    h2->epoch = kb->startepoch;
	    h2-> number_of_epochs = kb->numberofepochs;
	    /* this is the important number */
	    h2->requestedbits = newbitsneeded-kb->estimatedsamplesize;
	    insert_sendpacket((char *)h2, h2->bytelength);
	    break;
    }
    


    /* update thread */
    switch (replymode) {
	case 0: /* kill the thread due to excessive errors */
	    remove_thread(kb->startepoch);
	    break;
	case 1: /* wait for more bits to come */
	    kb->processingstate = PRS_GETMOREEST; 
	    break;
	case 2: /* error estimation is done, proceed to next step */
	    kb->processingstate = PRS_KNOWMYERROR;
	    kb->estimatedsamplesize = kb->leakagebits; /* is this needed? */
	    /****** more to do here *************/
	    /* calculate k0 and k1 for further uses */
	    if (localerror <0.01444) { kb->k0 = 64; /* min bitnumber */
	    } else { kb->k0 = (int) (0.92419642 / localerror); }
	    kb->k1 = 3*kb->k0; /* block length second array */
	    break;
    }

    return 0; /* everything went well */
}

/* ------------------------------------------------------------------------- */
/* function to reply to a request for more estimation bits. Argument is a
   pointer to the receive buffer containing the message. Just sends over a
   bunch of more estimaton bits. Currently, it uses only the PRNG method.

   Return value is 0 on success, or an error message otherwise. */
int send_more_esti_bits(char *receivebuf) {
    struct  ERRC_ERRDET_2 *in_head; /* holds header */
    struct keyblock *kb; /* poits to thread info */
    int bitsneeded; /* number of bits needed to send */
    struct  ERRC_ERRDET_0 *msg1; /* for header to be sent */

    /* get pointers for header...*/
    in_head = (struct  ERRC_ERRDET_2 *)receivebuf;

    /* ...and find thread: */
    kb = get_thread(in_head->epoch);
    if (!kb) {
	fprintf(stderr,"epoch %08x: ",in_head->epoch);
	return 49;
    }
    /* extract relevant information from thread */
    bitsneeded = in_head->requestedbits;

    /* prepare a response message block / fill the response with sample bits */
    msg1 = fillsamplemessage(kb, bitsneeded, 0,kb->BellValue);
    if (!msg1) return 43; /* a malloc error occured */

    /* adjust message reply to hide the seed/indicate a second reply */
    msg1->seed=0;
    /* send this structure to outgoing mailbox */
    insert_sendpacket((char *)msg1, msg1->bytelength);

    /* everything is fine */
    return 0;
}

/* for debug: output permutation */
void output_permutation(struct keyblock *kb) {
    char name[200] = "permutlist_";
    FILE* fp;
    int i;
    sprintf(name,"permutelist_%d",kb->role);
    fp=fopen(name,"w");
    for (i=0;i<kb->workbits;i++) 
	fprintf(fp,"%d %d\n",kb->permuteindex[i],kb->reverseindex[i]);
    fclose(fp);
}

/* -------------------------------------------------------------------------*/
/* permutation core function; is used both for biconf and initial
   permutation */
void prepare_permut_core(struct keyblock *kb) {
    int workbits;
    unsigned int rn_order;
    int i,j,k;
    workbits = kb->workbits;
    rn_order = get_order_2(workbits);

#ifdef SYSTPERMUTATION
    
    /* this prepares a systematic permutation  - seems not to be better, but
       blocknumber must be coprime with 127 - larger primes? */
    for (i=0;i<workbits;i++) {
	k=(127*i*kb->k0 + i*kb->k0/workbits)%workbits;
	kb->permuteindex[k]=i;
	kb->reverseindex[i]=k;
    }
#else 
    /* this is prepares a pseudorandom distribution */
    for (i=0;i<workbits;i++) kb->permuteindex[i] = 0xffff; /* mark unused */
    /* this routine causes trouble */
    for (i=0;i<workbits;i++) { /* do permutation  */
	do {  /* find a permutation index */
	    j = PRNG_value2(rn_order,&kb->RNG_state);
	} while ((j>=workbits) || 
		 (kb->permuteindex[j]!=0xffff)); /* out of range */
	k=j; 
	kb->permuteindex[k]=i;
	kb->reverseindex[i]=k;
    }
 
#endif

    bzero(kb->permutebuf, ((workbits+31)/32)*4); /* clear permuted buffer */
    for (i=0;i<workbits;i++) { /*  do bit permutation  */
	k=kb->permuteindex[i]; 
	if (bt_mask(i) & kb->mainbuf[i/32]) kb->permutebuf[k/32] |= bt_mask(k);
    } 

    /* for debug: output that stuff */
    /* output_permutation(kb); */

    return;
}


/* ------------------------------------------------------------------------- */
/* helper function to compress key down in a sinlge sequence to eliminate the
   revealeld bits. updates workbits accordingly, and reduces number of
   revealed bits in the leakage_bits_counter  */
void cleanup_revealed_bits(struct keyblock *kb) {
    int lastbit = kb->initialbits-1;
    unsigned int *d = kb->mainbuf; /* data buffer */
    unsigned int *m = kb->testmarker; /* index for spent bits */
    unsigned int bm; /* temp storage of bitmask */
    int i;

    /* find first nonused lastbit */
    while ((lastbit>0) && (m[lastbit/32]&bt_mask(lastbit))) lastbit--;
    
    /* replace spent bits in beginning by untouched bits at end */
    for (i=0;i<=lastbit;i++) {
	bm=bt_mask(i);
	if (m[i/32]&bm) { /* this bit is revealed */
	    d[i/32]= (d[i/32] & ~bm) | 
		((d[lastbit/32]&bt_mask(lastbit))?bm:0); /* transfer bit */
	    /* get new lastbit */
	    lastbit--;
	    while ((lastbit>0) && (m[lastbit/32]&bt_mask(lastbit))) lastbit--;
	}
    }
    /* i should now contain the number of good bits */
    kb->workbits = i;

    /* fill rest of buffer with zeros for not loosing any bits */
    d[i/32] &= ((i&31)?(0xffffffff<<(32-(i&31))):0);
    for (i=((kb->workbits/32)+1);i<(kb->initialbits+31)/32;i++) { 
	d[i]=0;
	/* printf("   i= %d\n",i); */
    }
    
    /* update number of lost bits */
    kb->leakagebits = 0;

    return;
}

/* -------------------------------------------------------------------------*/
/* helper function to do generate the permutation array in the kb structure.
   does also re-ordering (in future), and truncates the discussed key to a
   length of multiples of k1so there are noleftover bits in the two passes.
   Parameter: pointer to kb structure */
void prepare_permutation(struct keyblock *kb) {
    int workbits;
    unsigned int *tmpbuf;

    /* do bit compression */
    cleanup_revealed_bits(kb);
    workbits = kb->workbits;
    
    /* a quick-and-dirty cut for kb1 match, will change to reordering later.
       also: take more care about the leakage_bits here */
    
    /* assume last k1 block is filled with good bits and zeros */
    workbits = ((workbits/kb->k1)+1)*kb->k1;
    /* forget the last bits if it is larger than the buffer */
    if (workbits > kb->initialbits) workbits -= kb->k1;

    kb->workbits = workbits;

    /* do first permutation - this is only the initial permutation */
    prepare_permut_core(kb);
    /* now the permutated buffer is renamed and the final permutation is
       performed */
    tmpbuf=kb->mainbuf; kb->mainbuf=kb->permutebuf; kb->permutebuf = tmpbuf;
    /* fo final permutation */
    prepare_permut_core(kb);
    return;
}
 
/* helper function for parity isolation */
__inline__ unsigned int firstmask(int i) {
    return 0xffffffff>>i;
}
__inline__ unsigned int lastmask(int i) {
    return 0xffffffff<<(31-i);
}

/* helper function to preare a parity list of a given pass in a block.
   Parameters are a pointer to the sourcebuffer, pointer to the target buffer,
   and an integer arg for the blocksize to use, and the number of workbits */
void prepare_paritylist_basic(unsigned int *d, unsigned int *t, int k, int w) {
    int blkidx; /* contains blockindex */
    int bitidx; /* startbit index */
    unsigned int tmp_par; /* for combining parities */
    unsigned int resbuf; /* result buffer */
    int fi,li,ri; /* first and last and running bufferindex */
    unsigned int fm,lm; /* first mask, last mask */
   
    /* the bitindex points to the first and the last bit tested. */
    resbuf = 0; tmp_par = 0; blkidx=0;
    for (bitidx=0; bitidx<w; bitidx+=k) {
	fi=bitidx/32; fm=firstmask(bitidx&31); /* beginning */
	li=(bitidx+k-1)/32; lm = lastmask((bitidx+k-1)&31); /* end */
	if (li==fi) { /* in same word */
	    tmp_par=d[fi]&lm&fm;
	} else {
	    tmp_par=(d[fi]&fm) ^ (d[li]&lm);
	    for (ri=fi+1;ri<li;ri++) tmp_par ^= d[ri];
	} /* tmp_par holds now a combination of bits to be tested */
	resbuf = (resbuf<<1)+parity(tmp_par); /* shift parity result in buffer */
	 if ((blkidx & 31) ==31 ) t[blkidx/32]=resbuf;/* save in target */
	blkidx++;
    }
    /* cleanup residual parity buffer */
    if (blkidx & 31) t[blkidx/32]=resbuf<<(32-(blkidx & 31));
    return;
}


/* ------------------------------------------------------------------------- */
/* helper function to generate a pseudorandom bit pattern into the test bit
   buffer. parameters are a keyblock pointer, and a seed for the RNG.
   the rest is extracted out of the kb structure (for final parity test) */
void generate_selectbitstring(struct keyblock *kb, unsigned int seed){
    int i; /* number of bits to be set */
    kb->RNG_state = seed;  /* set new seed */
    for (i=0;i<(kb->workbits)/32;i++) /* take care of the full bits */
	kb->testmarker[i]=PRNG_value2_32(&kb->RNG_state);
    kb->testmarker[kb->workbits/32]= /* prepare last few bits */
	PRNG_value2_32(&kb->RNG_state) & lastmask((kb->workbits-1)& 31);
    return;
}

/* ------------------------------------------------------------------------- */
/* helper function to generate a pseudorandom bit pattern into the test bit
   buffer AND transfer the permuted key buffer into it for a more compact
   parity generation in the last round.
   Parameters are a keyblock pointer.
   the rest is extracted out of the kb structure (for final parity test) */
void generate_BICONF_bitstring(struct keyblock *kb){
    int i; /* number of bits to be set */
    for (i=0;i<(kb->workbits)/32;i++) {/* take care of the full bits */
	kb->testmarker[i] = 
	    PRNG_value2_32(&kb->RNG_state) 
	    & kb->permutebuf[i]; /* get permuted bit */
    }
    kb->testmarker[kb->workbits/32]= /* prepare last few bits */
	PRNG_value2_32(&kb->RNG_state) 
	& lastmask((kb->workbits-1)& 31) 
	& kb->permutebuf[kb->workbits/32];    
    return;
}

/* ----------------------------------------------------------------------- */
/* helper: count the number of set bits in a longint */
int count_set_bits(unsigned int a) {
    int c=0;
    unsigned int i;
    for (i=1;i;i<<=1) if (i&a) c++;
    return c;
}
/* helper function to preare a parity list of a given pass in a block, compare
   it with the received list and return the number of differing bits  */
int do_paritylist_and_diffs(struct keyblock *kb, int pass) {
    int numberofbits = 0;
    int i, partitions; /* counting index, num of blocks */
    unsigned int *lp, *rp, *pd; /* local/received & diff parity pointer */
    unsigned int *d; /* for paritylist */
    int k;
    switch (pass) {
	case 0:  k=kb->k0; d=kb->mainbuf;
	    lp=kb->lp0; rp=kb->rp0; pd= kb->pd0;
	    partitions=kb->partitions0;
	    break;
	case 1:  k=kb->k1; d=kb->permutebuf;
	    lp=kb->lp1; rp=kb->rp1; pd= kb->pd1;
	    partitions=kb->partitions1;
	    break;
	default: /* wrong index */
	    return -1;
    }
    prepare_paritylist_basic(d,lp,k,kb->workbits); /* prepare bitlist */
    

    /* evaluate parity mismatch  */
    for (i=0;i<((partitions+31)/32);i++) {
	pd[i]=lp[i]^rp[i];
	numberofbits+= count_set_bits(pd[i]);
    }
    return numberofbits;
}

/* helper function to prepare parity lists from original and unpermutated key.
   arguments are a pointer to the thread structure, a pointer to the target 
   parity buffer 0 and another pointer to paritybuffer 1. No return value,
   as no errors are tested here. */
void prepare_paritylist1(struct keyblock *kb,
			 unsigned int *d0, unsigned int *d1) {    
    prepare_paritylist_basic(kb->mainbuf, d0, kb->k0, kb->workbits);
    prepare_paritylist_basic(kb->permutebuf, d1, kb->k1, kb->workbits);
    return;
}

/* ------------------------------------------------------------------------- */
/* function to proceed with the error estimation reply. Estimates if the 
   block deserves to be considered further, and if so, prepares the permutation
   array of the key, and determines the parity functions of the first key.
   Return value is 0 on success, or an error message otherwise. */
int prepare_dualpass(char *receivebuf) {
    struct  ERRC_ERRDET_3 *in_head; /* holds header */
    struct keyblock *kb; /* poits to thread info */
    float localerror,ldi;
    int errormark, newbitsneeded;
    unsigned int newseed; /* seed for permutation */
    int msg4datalen;
    struct ERRC_ERRDET_4 *h4; /* header pointer */
    unsigned int *h4_d0, *h4_d1; /* pointer to data tracks  */
    int retval;
    
    /* get pointers for header...*/
    in_head = (struct  ERRC_ERRDET_3 *)receivebuf;
    
    /* ...and find thread: */
    kb = get_thread(in_head->epoch);
    if (!kb) {
	fprintf(stderr,"epoch %08x: ",in_head->epoch);
	return 49;
    }
    /* extract error information out of message */
    if (in_head->tested_bits != kb->leakagebits) return 52;
    kb->estimatedsamplesize = in_head->tested_bits;
    kb->estimatederror = in_head->number_of_errors;

    /* decide if to proceed */
    if (kb->errormode) {
	localerror = (float)kb->initialerror/65536.;
    } else {
	localerror=(float)kb->estimatederror/(float)kb->estimatedsamplesize; 
	ldi=USELESS_ERRORBOUND-localerror;
	errormark=0;
	if (ldi <= 0.) {
	    errormark=1; /* will not work */
	} else {
	    newbitsneeded =  testbits_needed(localerror);
	    if (newbitsneeded > kb->initialbits) { /* will never work */
		errormark = 1;
	    } 
	}
	if (errormark) {/* not worth going */
	    remove_thread(kb->startepoch);
	    return 0;
	}
    }

    /* determine process variables */
    kb->processingstate = PRS_KNOWMYERROR;

    kb->estimatedsamplesize = kb->leakagebits; /* is this needed? */

    /****** more to do here *************/
    /* calculate k0 and k1 for further uses */
    if (localerror <0.01444) { kb->k0 = 64; /* min bitnumber */
    } else { kb->k0 = (int) (0.92419642 / localerror); }
    kb->k1 = 3*kb->k0; /* block length second array */
    
    /* install new seed */
    kb->RNG_usage = 0; /* use simple RNG */
    if (!(newseed = get_r_seed())) return 39; 
    kb->RNG_state = newseed;  /* get new seed for RNG */
    
    /* prepare permutation array */
    prepare_permutation(kb);

    /* prepare message 5 frame - this should go into prepare_permutation? */
    kb->partitions0 = (kb->workbits + kb->k0-1) / kb->k0; 
    kb->partitions1 = (kb->workbits + kb->k1-1) / kb->k1;

    /* get raw buffer */
    msg4datalen = ((kb->partitions0+31)/32+(kb->partitions1+31)/32)*4;
    h4 = (struct ERRC_ERRDET_4 *)
	malloc2(sizeof(struct ERRC_ERRDET_4)+msg4datalen);
    if (!h4) return 43; /* cannot malloc */
    /* both data arrays */
    h4_d0 = (unsigned int *)&h4[1];
    h4_d1 = &h4_d0[(kb->partitions0+31)/32];
    h4->tag = ERRC_PROTO_tag;
    h4->bytelength = sizeof(struct ERRC_ERRDET_4)+msg4datalen;
    h4->subtype = ERRC_ERRDET_4_subtype;
    h4->epoch = kb->startepoch;
    h4->number_of_epochs = kb->numberofepochs;  /* length of the block */
    h4->seed = newseed; /* permutator seed */

    /* these are optional; should we drop them? */
    h4->k0 = kb->k0;  h4->k1 = kb->k1; h4->totalbits = kb->workbits;
    
    /* evaluate parity in blocks */
    prepare_paritylist1(kb, h4_d0, h4_d1);
  
    /* update status */
    kb->processingstate = PRS_PERFORMEDPARITY1;
    kb->leakagebits += kb->partitions0 + kb->partitions1;

    /* transmit message */
    retval=insert_sendpacket((char *)h4, h4->bytelength);
    if (retval) return retval;

    return 0; /* go dormant again... */
}



/* ----------------------------------------------------------------------- */
/* function to prepare the first message head for a binary search. This assumes
   that all the parity buffers have been malloced and the remote parities
   reside in the proper arrays. This function will be called several times for
   different passes; it expexts local parities to be evaluated already.
   Arguments are a keyblock pointer, and a pass number. returns 0 on success,
   or an error code accordingly. */
int prepare_first_binsearch_msg(struct keyblock *kb, int pass) {
    int i,j; /* index variables */
    int k; /* length of keyblocks */
    unsigned int *pd; /* parity difference bitfield pointer */
    unsigned int msg5size;        /* size of message */
    struct ERRC_ERRDET_5 *h5;     /* pointer to first message */
    unsigned int *h5_data, *h5_idx; /* data pointers */
    unsigned int *d; /* temporary pointer on parity data */
    unsigned int resbuf, tmp_par, lm,fm; /* parity determination variables */
    int kdiff, fbi, lbi, fi, li, ri; /* working variables for parity eval */
    int partitions; /* local partitions o go through for diff idx */

    switch (pass) { /* sort out specifics */
	case 0: /* unpermutated pass */
	    pd=kb->pd0; k=kb->k0; partitions = kb->partitions0;
	    d=kb->mainbuf; /* unpermuted key */
	    break;
	case 1: /* permutated pass */
	    pd=kb->pd1; k=kb->k1;partitions = kb->partitions1;
	    d=kb->permutebuf; /* permuted key */
	    break;
	default: /* illegal */
	    return 59; /* illegal pass arg */
    }
    

    /* fill difference index memory */
    j=0; /* index for mismatching blocks */
    for (i=0;i<partitions;i++) {
	if (bt_mask(i) & pd[i/32]) { /* this block is mismatched */
	    kb->diffidx[j]=i*k;  /* store bit index, not block index */
	    kb->diffidxe[j]=i*k+(k-1); /* last block */
	    j++;
	}
    }
   /* mark pass/round correctly in kb */
    kb->binsearch_depth =  (pass==0?RUNLEVEL_FIRSTPASS:RUNLEVEL_SECONDPASS)
	| 0; /* first round */

    /* prepare message buffer for first binsearch message  */
    msg5size = sizeof(struct ERRC_ERRDET_5 ) /* header need */
	+ ((kb->diffnumber+31)/32)*sizeof(unsigned int) /* parity data need */
	+ kb->diffnumber*sizeof(unsigned int); /* indexing need */
    h5 = (struct ERRC_ERRDET_5 *)malloc2(msg5size);
    if (!h5) return 55;
    h5_data = (unsigned int *) &h5[1]; /* start of data */
    h5->tag = ERRC_PROTO_tag; h5->subtype = ERRC_ERRDET_5_subtype;
    h5->bytelength = msg5size; h5->epoch = kb->startepoch;
    h5->number_of_epochs = kb->numberofepochs;
    h5->number_entries = kb->diffnumber;
    h5->index_present = 1; /* this round we have an index table */
    h5->runlevel = kb->binsearch_depth; /* keep local status */

    /* prepare block index list of simple type 1, uncompressed uint32 */
    h5_idx = &h5_data[((kb->diffnumber+31)/32)];
    for (i=0;i<kb->diffnumber;i++) h5_idx[i]=kb->diffidx[i];

    /* prepare parity results */
    resbuf=0; tmp_par=0;
    for (i=0;i<kb->diffnumber;i++) { /* go through all keyblocks */
	kdiff = kb->diffidxe[i]-kb->diffidx[i]+1; /* left length */
	fbi = kb->diffidx[i];lbi = fbi + kdiff/2-1; /* first and last bitidx */
	fi=fbi/32; fm=firstmask(fbi&31); /* beginning */
	li=lbi/32; lm = lastmask(lbi&31); /* end */
	if (li==fi) { /* in same word */
	    tmp_par=d[fi]&lm&fm;
	} else {
	    tmp_par=(d[fi]&fm) ^ (d[li]&lm);
	    for (ri=fi+1;ri<li;ri++) tmp_par ^= d[ri];
	} /* tmp_par holds now a combination of bits to be tested */
	resbuf = (resbuf <<1) + parity(tmp_par);
	if ((i&31)==31) {
	    h5_data[i/32]=resbuf;
	}
    }
    if (i&31) h5_data[i/32]=resbuf<<(32-(i&31)); /* last parity bits */
    

    /* increment lost bits */
    kb->leakagebits += kb->diffnumber;

    /* send out message */
    insert_sendpacket((char *)h5, msg5size);

    return 0;
}
   
/* ------------------------------------------------------------------------- */
/* function to proceed with the parity evaluation message. This function 
   should start the Binary search machinery. 
   Argument is receivebuffer as usual, returnvalue 0 on success or err code.
   Should spit out the first binary search message */

int start_binarysearch(char *receivebuf) {
    struct  ERRC_ERRDET_4 *in_head; /* holds received message header */
    struct keyblock *kb; /* points to thread info */
    int l0, l1; /* helpers;  number of words for bitarrays */

    /* get pointers for header...*/
    in_head = (struct  ERRC_ERRDET_4 *)receivebuf;
    
    /* ...and find thread: */
    kb = get_thread(in_head->epoch);
    if (!kb) {
	fprintf(stderr,"epoch %08x: ",in_head->epoch);
	return 49;
    }

    /* prepare local parity info */
    kb->RNG_state = in_head->seed; /* new rng seed */
    prepare_permutation(kb); /* also updates workbits */
    
    /* update partition numbers and leakagebits */
    kb->partitions0 = (kb->workbits + kb->k0-1) / kb->k0; 
    kb->partitions1 = (kb->workbits + kb->k1-1) / kb->k1;

    /* freshen up internal info on bit numbers etc */
    kb->leakagebits += kb->partitions0 + kb->partitions1;
    
    /* prepare parity list and difference buffers  */
    l0=(kb->partitions0+31)/32; l1=(kb->partitions1+31)/32; /* size in words */
    kb->lp0 = (unsigned int *)malloc2((l0+l1)*4*3);
    if (!kb->lp0) return 53; /* can't malloc */
    kb->lp1 = &kb->lp0[l0]; /* ptr to permuted parities */
    kb->rp0 = &kb->lp1[l1]; /* prt to rmt parities 0 */
    kb->rp1 = &kb->rp0[l0]; /* prt to rmt parities 1 */
    kb->pd0 = &kb->rp1[l1]; /* prt to rmt parities 0 */
    kb->pd1 = &kb->pd0[l0]; /* prt to rmt parities 1 */


    /* store received parity lists as a direct copy into the rp structure */
    memcpy(kb->rp0, &in_head[1], /* this is the start of the data section */
	   (l0+l1)*4);

    /* fill local parity list, get the number of differences */
    kb->diffnumber = do_paritylist_and_diffs(kb, 0);
    if (kb->diffnumber == -1) return 74;
    kb->diffnumber_max = kb->diffnumber;
    
    /* reserve difference index memory for pass 0 */
    kb->diffidx=(unsigned int *)malloc2(kb->diffnumber*sizeof(unsigned int)*2);
        if (!kb->diffidx) return 54; /* can't malloc */
    kb->diffidxe = &kb->diffidx[kb->diffnumber]; /* end of interval */

    /* now hand over to the procedure preoaring the first binsearch msg 
       for the first pass 0 */

    return prepare_first_binsearch_msg(kb,0);
}

/* ------------------------------------------------------------------------- */
/* helper function for binsearch replies; mallocs and fills msg header */
struct ERRC_ERRDET_5 *make_messagehead_5(struct keyblock *kb) {
    int msglen; /* length of outgoing structure (data+header) */
    struct ERRC_ERRDET_5 *out_head; /* return value */
    msglen = ((kb->diffnumber+31)/32)*4*2 +  /* two bitfields */
	sizeof(struct ERRC_ERRDET_5); /* ..plus one header */
    out_head = (struct ERRC_ERRDET_5 *)malloc2(msglen);
    if (!out_head) return NULL;
    out_head->tag =  ERRC_PROTO_tag; out_head->bytelength = msglen;
    out_head->subtype = ERRC_ERRDET_5_subtype;
    out_head->epoch = kb->startepoch;
    out_head->number_of_epochs = kb->numberofepochs;
    out_head->number_entries = kb->diffnumber;
    out_head->index_present = 0; /* this is an ordidary reply */
    out_head->runlevel = kb->binsearch_depth; /* next round */

    return out_head;
}
/* helper program to half parity difference intervals ; takes kb and inh_index
   as parameters; no weired stuff should happen. return value is the number
   of initially dead intervals */
void fix_parity_intervals(struct keyblock *kb, unsigned int *inh_idx) {
    int i,fbi,lbi; /* running index */
    for (i=0;i<kb->diffnumber;i++) { /* go through all different blocks */
	fbi=kb->diffidx[i]; 
	lbi=kb->diffidxe[i]; /* old bitindices */
	if (fbi>lbi){
	    /* was already old */
	    continue;
	}
	if (inh_idx[i/32]&bt_mask(i)) { /* error is in upper (par match) */
	    kb->diffidx[i]=fbi+(lbi-fbi+1)/2; /* take upper half */
	} else {
	    kb->diffidxe[i]=fbi+(lbi-fbi+1)/2-1;/* take lower half */
	}
    }   
}

/* helper for correcting one bit in pass 0 or 1 in their field */
void correct_bit(unsigned int *d, int bitindex) {
    d[bitindex/32] ^= bt_mask(bitindex); /* flip bit */
    return;
}
/* helper to fix the permuted/unpermuted bit changes; decides via a parameter
   in kb->binsearch_depth MSB what polarity to take */
void fix_permutedbits(struct keyblock *kb) {
    int i,k;
    unsigned int *src, *dst;
    unsigned short *idx; /* pointers to data loc and permute idx */
    if (kb->binsearch_depth & RUNLEVEL_LEVELMASK) { /* we are in pass 1 */
	src=kb->permutebuf; dst=kb->mainbuf; idx=kb->reverseindex;
    } else { /* we are in pass 0 */
	src=kb->mainbuf; dst=kb->permutebuf; idx=kb->permuteindex;
    }
    bzero(dst,((kb->workbits+31)/32)*4); /* clear dest */
    for (i=0;i<kb->workbits;i++) {
	k=idx[i]; /* permuted bit index */
	if (bt_mask(i) & src[i/32]) dst[k/32] |= bt_mask(k);
    }
    return;
}
/* ------------------------------------------------------------------------- */
/* function to process a binarysearch request on alice identity. Installs the
   difference index list in the first run, and performs the parity checks in
   subsequent runs. should work with both passes now
   - work in progress, need do fix bitloss in last round 
 */
int process_binsearch_alice (
    struct keyblock *kb, struct ERRC_ERRDET_5 *in_head) {
    unsigned int *inh_data, *inh_idx;
    int i;
    struct ERRC_ERRDET_5 *out_head; /* for reply message */
    unsigned int *out_parity; /* pointer to outgoing parity result info */
    unsigned int *out_match; /* pointer to outgoing matching info */
    unsigned int *d; /* points to internal key data */
    int k; /* keeps blocklength */
    unsigned int matchresult=0, parityresult=0; /* for builduing outmsg */
    unsigned int fm, lm, tmp_par; /* for parity evaluation */
    int fbi,lbi, mbi, fi, li, ri; /* for parity evaluation */
    int lost_bits; /* number of key bits revealed in this round */

    inh_data = (unsigned int *) &in_head[1]; /* parity pattern */

    /* find out if difference index should be installed */
    while (in_head->index_present) {
	if (kb->diffidx) { /* there is already a diffindex */
	    if (kb->diffnumber_max>=in_head->number_entries ){
		/* just re-assign */
		kb->diffnumber = in_head->number_entries;
		break;
	    }
	    /* otherwise: not enough space; remove the old one... */
	    free2(kb->diffidx); 
	    /* ....and continue re-assigning... */
	}
	/* allocate difference idx memory */
	kb->diffnumber =in_head->number_entries; /* from far cons check? */
	kb->diffnumber_max = kb->diffnumber;
	kb->diffidx=(unsigned int *)
	malloc2(kb->diffnumber*sizeof(unsigned int)*2);
	if (!kb->diffidx) return 54; /* can't malloc */
	kb->diffidxe = &kb->diffidx[kb->diffnumber]; /* end of interval */
	break;
    }

    inh_idx = &inh_data[(kb->diffnumber+31)/32]; /* index or matching part */

    /* sort out pass-dependent variables */
    if (in_head->runlevel &  RUNLEVEL_LEVELMASK) { /* this is pass 1 */
	d=kb->permutebuf; k = kb->k1; 
    } else { /* this is pass 0 */
	d=kb->mainbuf; k = kb->k0;
    }

    /* special case to take care of if this is a BICONF localizing round:
       the variables d and k contain worng values at this point.
       this is taken care now */
    if (in_head->runlevel & RUNLEVEL_BICONF) {
	d=kb->testmarker; k=kb->biconflength;
    }
    
    /* fix index list according to parity info or initial run */
    switch (in_head->index_present) { /* different encodings */
	case 0: /* repair index according to previous basis match */
	    fix_parity_intervals(kb, inh_idx);
	    break;
	case 1: /* simple unsigned int encoding */
	    for (i=0;i<kb->diffnumber;i++) {
		kb->diffidx[i]=inh_idx[i]; /* store start bit index */
		kb->diffidxe[i]=inh_idx[i]+(k-1); /* last bit */
	    }
	    break;
	case 4: /* only one entry; from biconf run. should end be biconflen? */
	    kb->diffidx[0]=inh_idx[0];kb->diffidxe[0]=kb->workbits-1;
	    break;
	    /* should have a case 3 here for direct bit encoding */
	default: /* do not know encoding */
	    return 57;
    }
    
    /* other stuff in local keyblk to update */
    kb->leakagebits += kb->diffnumber; /* for incoming parity bits */
    /* check if this masking is correct? let biconf status survive  */
    kb->binsearch_depth = ((in_head->runlevel +1) & RUNLEVEL_ROUNDMASK)
	+ (in_head->runlevel & (RUNLEVEL_LEVELMASK | RUNLEVEL_BICONF));
    
    /* prepare outgoing message header */
    out_head = make_messagehead_5(kb); if (!out_head) return 58;
    out_parity = (unsigned int *) &out_head[1];
    out_match = &out_parity[(kb->diffnumber+31)/32];

    lost_bits = kb->diffnumber; /* to keep track of lost bits */
 
    /* go through all entries */
    for (i=0;i<kb->diffnumber;i++) {
	parityresult<<=1; matchresult <<=1; /* make more room */
	/* first, determine parity on local inverval */
	fbi=kb->diffidx[i]; lbi = kb->diffidxe[i]; /* old bitindices */
	if (fbi>lbi) { /* this is an empty message */
	    lost_bits-=2;
	    goto skpar2;
	}
	if (fbi==lbi) {
	    lost_bits-=2; /* one less lost on receive, 1 not sent */
	    kb->diffidx[i]=fbi+1; /* mark as emty */
	    goto skpar2; /* no parity eval needed */
	}
	mbi = fbi + (lbi - fbi +1)/2 - 1; /* new lower mid bitidx */
	fi=fbi/32; li=mbi/32; fm =firstmask(fbi&31); lm= lastmask(mbi&31); 
	if (fi==li) { /* in same word */
	    tmp_par = d[fi]&fm&lm;
	} else {
	    tmp_par = (d[fi]&fm) ^ (d[li]&lm);
	    for (ri=fi+1;ri<li;ri++) tmp_par ^=d[ri];
	} /* still need to parity tmp_par */
	if (((inh_data[i/32]&bt_mask(i))?1:0)==parity(tmp_par)) {
	    /* same parity, take upper half */
	    fbi=mbi+1; kb->diffidx[i]=fbi; /* update first bit idx */
	    matchresult |=1; /* match with incoming parity (take upper) */
	} else {
	    lbi=mbi; kb->diffidxe[i]=lbi; /* update last bit idx */
	}

	/* test overlap.... */
	if (fbi==lbi) {
	    lost_bits--; /* one less lost */
	    goto skpar2; /* no parity eval needed */
	}

	/* now, prepare new parity bit */
	mbi = fbi + (lbi - fbi +1)/2 - 1; /* new lower mid bitidx */
	fi=fbi/32; li=mbi/32; fm =firstmask(fbi&31); lm= lastmask(mbi&31);
	if (fi==li) { /* in same word */
	    tmp_par = d[fi]&fm&lm;
	} else {
	    tmp_par = (d[fi]&fm) ^ (d[li]&lm);
	    for (ri=fi+1;ri<li;ri++) tmp_par ^=d[ri];
	} /* still need to parity tmp_par */
	if (lbi<mbi) { /* end of interval, give zero parity */
	    tmp_par=0; 
	}
	parityresult |=  parity(tmp_par); /* save parity */
    skpar2:
	if ((i&31) == 31) { /* save stuff in outbuffers */
	    out_match[i/32]=matchresult; out_parity[i/32]=parityresult;
	}
    }
    /* cleanup residual bit buffers */
    if (i & 31 ) { 
	out_match[i/32]  = matchresult  << (32-(i&31));
	out_parity[i/32] = parityresult << (32-(i&31));
    }

    
    /* update outgoing info leakagebits */
    kb->leakagebits += lost_bits;

    /* mark message for sending */
    insert_sendpacket((char *)out_head, out_head->bytelength);
    
    return 0;
}


/* ------------------------------------------------------------------------- */
/* function to initiate a BICONF procedure on Bob side. Basically sends out a
   package calling for a BICONF reply. Parameter is a thread pointer, and
   the return value is 0 or an error code in case something goes wrong.   */
int initiate_biconf(struct keyblock *kb) {
    struct ERRC_ERRDET_6 *h6; /* header for that message */
    unsigned int seed; /* seed for permutation */

    h6 = (struct ERRC_ERRDET_6 *)malloc2(sizeof(struct ERRC_ERRDET_6));
    if (!h6) return 60;

    /* prepare seed */
    seed = get_r_seed();

    /* update state variables */
    kb->biconflength = kb->workbits; /* old was /2 - do we still need this? */
    kb->RNG_state = seed;

    /* generate local bit string for test mask */
    generate_BICONF_bitstring(kb);
    
    /* fill message */
    h6->tag = ERRC_PROTO_tag; h6->bytelength=sizeof(struct ERRC_ERRDET_6);
    h6->subtype = ERRC_ERRDET_6_subtype;
    h6->epoch = kb->startepoch; h6->number_of_epochs = kb->numberofepochs;
    h6->seed = seed;
    h6->number_of_bits = kb->biconflength;
    kb->binsearch_depth=0; /* keep it to main buffer TODO: is this relevant? */
    
    /* submit message */
    insert_sendpacket((char *)h6, h6->bytelength);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* helper: eve's error knowledge */
float phi(float z){return ((1+z)*log(1+z)+(1-z)*log(1-z))/log(2.);};
float binentrop(float q){return (-q*log(q)-(1-q)*log(1-q))/log(2.);}
/* ------------------------------------------------------------------------- */
/* do core part of the privacy amplification. Calculates the compression ratio
   based on the lost bits, saves the final key and removes the thread from the
   list.    */
int do_privacy_amplification(struct keyblock *kb, unsigned int seed, 
			     int lostbits) {
    int sneakloss;
    float trueerror, cheeky_error, safe_error;
    unsigned int *finalkey; /* pointer to final key */
    unsigned int m; /* addition register */
    int numwords, mlen; /* number of words in final key / message length */
    struct header_7 *outmsg; /* keeps output message */
    int i,j; /* counting indices */
    char ffnam[FNAMELENGTH+10]; /* to store filename */
    int written, rv; /* counts writeout bits, return value */
    int redundantloss; /* keeps track of redundancy in error correction */
    float BellHelper;

    /* determine final key size */
    /* redundancy in parity negotiation; we transmit the last bit which could#
       be deducked from tracking the whole parity information per block. For
       each detected error, there is one bit redundant, which is overcounted
       in the leakage */
    redundantloss=kb->correctederrors; 

    /* This is the error rate found in the error correction process. It should
       be a fair representation of the errors on that block of raw key bits,
       but a safety margin on the error of the error should be added, e.g.
       in terms of multiples of the standard deviation assuming a poissonian
       distribution for errors to happen (not sure why this is a careless
       assumption in the first place either. */
    trueerror = (float) kb->correctederrors / (float) kb->workbits;

    /* This 'intrisic error' thing is very dodgy, it should not be used at all
       unless you know what Eve is doing (which by definition you don't).
       Therefore, it s functionality is mostly commented out, only the 
       basic query remains. The idea is based on the hope ventilated 
       at some point that there is a basic error (of the kind of a detector
       dark count rate) which does lead to any information
       loss to the eavesdropper. Relies on lack of imagination how an
       eavesdropper can influence this basic error rather than on fundamental
       laws. Since this is dirty, we might as well assume that such an error
       is UNCORRELATED to errors caused by potential eavesdropping, and
       assume they add quadratically. Let's at least check that the true
       error is not smaller than the "basic" error..... */
    if (intrinsicerr < trueerror) {
	cheeky_error = sqrt(trueerror*trueerror-intrinsicerr*intrinsicerr);
	
	/* Dodgy intrinsic error subtraction would happen here. */

	/* We now evaluate the knowledge of an eavesdropper on the initial raw
	   key for a given error rate, excluding the communication on error
	   correction */
	if (!bellmode) { /* do single-photon source bound */

	    if (kb->correctederrors>0) {
		safe_error = 
		    trueerror*(1.+errormargin/sqrt(kb->correctederrors));
	    } else {
		safe_error = trueerror;
	    }
	    sneakloss = (int)(binentrop(safe_error)*kb->workbits);

	    /* old version of the loss to eve:
	       sneakloss =
	      (int)(phi(2*sqrt(trueerror*(1-trueerror)))/2.*kb->workbits);
	    */
	} else { /* we do the device-indepenent estimation */
	    BellHelper=kb->BellValue* kb->BellValue/4.-1.;
	    if (BellHelper<0.) { /* we have no key...*/
		sneakloss=kb->workbits;
	    } else { /* there is hope... */
		sneakloss=(int)
		    (kb->workbits*binentrop((1.+sqrt(BellHelper))/2.));
	    }
	}
    } else {
	sneakloss = 0; /* Wruaghhh - how dirty... */
    }

    /* here we do the accounting of gained and lost bits */
    kb->finalkeybits = kb->workbits-(kb->leakagebits+sneakloss)+redundantloss;
    if (kb->finalkeybits<0) kb->finalkeybits=0; /* no hope. */

    /* dirtwork for testing. I need to leave this in because it is the basis
     for may of the plots we have. */
    printf("PA disable: %d\n",disable_privacyamplification);

    if (disable_privacyamplification) {
	kb->finalkeybits = kb->workbits; }

    printf("before privacy amp:\n corrected errors: %d\n workbits: %d\n",
	   kb->correctederrors, kb->workbits);
    printf(" trueerror: %f\n sneakloss: %d\n leakagebits: %d\n",
	   trueerror, sneakloss, kb->leakagebits-redundantloss);
    printf(" finakeybits: %d\n",kb->finalkeybits);

    /* initiate seed */
    kb->RNG_state=seed;
    
    /* set last bits to zero in workbits.... */
    numwords=(kb->workbits+31)/32;
    if (kb->workbits & 31) kb->mainbuf[numwords-1] &= 
			       (0xffffffff<<(32-(kb->workbits&31)));


    /* prepare structure for final key */
    mlen = sizeof(struct header_7)+((kb->finalkeybits+31)/32)*4;
    outmsg = (struct header_7 *)malloc2(mlen);
    if (!outmsg) return 63;
    outmsg->tag = TYPE_7_TAG; /* final key file */
    outmsg->epoc = kb->startepoch;
    outmsg->numberofepochs = kb->numberofepochs; 
    outmsg->numberofbits = kb->finalkeybits;

    finalkey = (unsigned int *) &outmsg[1]; /* here starts data area */

    /* clear target buffer */
    bzero(finalkey, (kb->finalkeybits+31)/32*4);


    /* prepare final key */
    if (disable_privacyamplification) { /* no PA fo debugging */
	for (j=0;j<numwords;j++) finalkey[j]=kb->mainbuf[j];
    } else { /* do privacy amplification */
	/* create compression matrix on the fly while preparing key */
	for (i=0;i<kb->finalkeybits;i++) { /* go through all targetbits */
	    m=0; /* initial word */
	    for (j=0;j<numwords;j++) m ^= (kb->mainbuf[j] &
					   PRNG_value2_32(&kb->RNG_state));
	    if (parity(m)) finalkey[i/32] |= bt_mask(i);
	}
    }

    /* send final key to file */ 
    strncpy(ffnam, fname[4], FNAMELENGTH); /* fnal key directory */
    atohex(&ffnam[strlen(ffnam)],kb->startepoch); /* add file name */
    handle[4]=open(ffnam, FILEOUTMODE, OUTPERMISSIONS); /* open target */
    if (-1==handle[4]) return 64;
    written=0;
    while(1) {
	rv=write(handle[4], &((char *)outmsg)[written], mlen-written);
	if (rv==-1) return 65; /* write error happened */
	written +=rv;
	if (written>=mlen) break;
	usleep(100000); /* sleep 100 msec */
    }
    close(handle[4]);
    
    /* send notification */
    switch (verbosity_level) {
	case 0: /* output raw block name */
	    fprintf(fhandle[5],"%08x\n",kb->startepoch);
	    break;
	case 1: /* block name and final bits */
	    fprintf(fhandle[5],"%08x %d\n",kb->startepoch,kb->finalkeybits);
	    break;
	case 2: /* block name, ini bits, final bits, error rate */
	    fprintf(fhandle[5],"%08x %d %d %.4f\n",
		    kb->startepoch,kb->initialbits,kb->finalkeybits,trueerror);
	    break;
	case 3: /* same as with 2 but with text */
	    fprintf(fhandle[5],
		    "startepoch: %08x initial bit number: %d final bit number: %d error rate: %.4f\n",
		    kb->startepoch,kb->initialbits,kb->finalkeybits,trueerror);
	    break;
	case 4: /* block name, ini bits, final bits, error rate, leak bits */
	    fprintf(fhandle[5],"%08x %d %d %.4f %d\n",
		    kb->startepoch,kb->initialbits,kb->finalkeybits,trueerror,
		    kb->leakagebits);
	    break;
	case 5: /* same as with 4 but with text */
	    fprintf(fhandle[5],
		    "startepoch: %08x initial bit number: %d final bit number: %d error rate: %.4f leaked bits in EC: %d\n",
		    kb->startepoch,kb->initialbits,kb->finalkeybits,trueerror,
		    kb->leakagebits);
	    break;
    }
    
    fflush(fhandle[5]);
    /* cleanup outmessage buf */
    free2(outmsg);

    /* destroy thread */
    printf("remove thread\n");fflush(stdout);
    return remove_thread(kb->startepoch);
    

    /* return benignly */
    return 0;
}

/* ------------------------------------------------------------------------- */
/* function to initiate the privacy amplification. Sends out a message with
   a PRNG seed (message 8), and hand over to the core routine for the PA.
   Parameter is keyblock, return is error or 0 on success. */
int initiate_privacyamplification(struct keyblock *kb) {
    unsigned int seed;
    struct  ERRC_ERRDET_8 *h8; /* head for trigger message */
    
    /* generate local RNG seed */
    seed=get_r_seed();

    /* prepare messagehead */
    h8=(struct ERRC_ERRDET_8 *)malloc2(sizeof(struct ERRC_ERRDET_8));
    if (!h8) return 62; /* can't malloc */
    h8->tag=ERRC_PROTO_tag; h8->bytelength = sizeof (struct ERRC_ERRDET_8);
    h8->subtype = ERRC_ERRDET_8_subtype; h8->epoch=kb->startepoch;
    h8->number_of_epochs=kb->numberofepochs;
    h8->seed = seed; /* significant content */
    h8->lostbits = kb->leakagebits; /* this is what we use for PA */
    h8->correctedbits = kb->correctederrors;
    
    /* insert message in msg pool */
    insert_sendpacket((char *)h8, h8->bytelength);

    /* do actual privacy amplification */
    return do_privacy_amplification(kb, seed, kb->leakagebits);
}
/* ------------------------------------------------------------------------- */
/* function to process a privacy amplification message. parameter is incoming
   message, return value is 0 or an error code. Parses the message and passes
   the real work over to the do_privacyamplification part */
int receive_privamp_msg(char *receivebuf) {
    struct  ERRC_ERRDET_8 *in_head; /* holds header */
    struct keyblock *kb; /* poits to thread info */

    /* get pointers for header...*/
    in_head = (struct  ERRC_ERRDET_8 *)receivebuf;
    
    /* ...and find thread: */
    kb = get_thread(in_head->epoch);
    if (!kb) {
	fprintf(stderr,"epoch %08x: ",in_head->epoch);
	return 49;
    }
    
    /* retreive number of corrected bits */
    kb->correctederrors = in_head->correctedbits;

    /* do some consistency checks???*/

    /* pass to the core prog */
    return do_privacy_amplification(kb, in_head->seed, in_head->lostbits);
}

/* ------------------------------------------------------------------------- */
/* function to process a binarysearch request on bob identity. Checks parity
   lists and does corrections if necessary. 
   initiates the next step (BICONF on pass 1) for the next round if ready.
*/
int process_binsearch_bob (
    struct keyblock *kb, struct ERRC_ERRDET_5 *in_head) {
        unsigned int *inh_data, *inh_idx;
    int i;
    struct ERRC_ERRDET_5 *out_head; /* for reply message */
    unsigned int *out_parity; /* pointer to outgoing parity result info */
    unsigned int *out_match; /* pointer to outgoing matching info */
    unsigned int *d=NULL; /* points to internal key data */
    unsigned int *d2=NULL; /* points to secondary to-be-corrected buffer */
    unsigned int matchresult=0, parityresult=0; /* for builduing outmsg */
    unsigned int fm, lm, tmp_par; /* for parity evaluation */
    int fbi,lbi, mbi, fi, li, ri; /* for parity evaluation */
    int lost_bits; /* number of key bits revealed in this round */
    int thispass; /* indincates the current pass */
    int biconfmark; /* indicates if this is a biconf round */

    inh_data = (unsigned int *) &in_head[1]; /* parity pattern */
    inh_idx = &inh_data[(kb->diffnumber+31)/32]; /* index or matching part */


    /* repair index according to previous basis match */
    fix_parity_intervals(kb, inh_idx);   

    /* other stuff in local keyblk to update */
    kb->leakagebits += kb->diffnumber; /* for incoming parity bits */
    kb->binsearch_depth = in_head->runlevel+1; /* better some checks? */
    
    /* prepare outgoing message header */
    out_head = make_messagehead_5(kb); if (!out_head) return 58;
    out_parity = (unsigned int *) &out_head[1];
    out_match = &out_parity[((kb->diffnumber+31)/32)];
   
    lost_bits = kb->diffnumber; /* initially we will loose those for outgoing 
				   parity bits */

    /* make pass-dependent settings */
    thispass = (kb->binsearch_depth & RUNLEVEL_LEVELMASK)?1:0;

    switch (thispass) { 
	case 0:/* level 0 */
	    d=kb->mainbuf;
	    break;
	case 1: /* level 1 */
	    d=kb->permutebuf;
    }
    
    biconfmark=0; /* default is no biconf */

    /* select test buffer in case this is a BICONF test round */
    if (kb->binsearch_depth & RUNLEVEL_BICONF) {
	biconfmark=1;
	d=kb->testmarker;
	d2=kb->permutebuf; /* for repairing also the permuted buffer */
    }
    
    /* go through all entries */
    for (i=0;i<kb->diffnumber;i++) {
	matchresult <<=1; parityresult <<=1;/* make room for next bits */
	/* first, determine parity on local inverval */
	fbi=kb->diffidx[i]; lbi = kb->diffidxe[i]; /* old bitindices */

	if (fbi>lbi) { /* this is an empty message , don't count or correct */
	    lost_bits-=2; /* No initial parity, no outgoing */
	    goto skipparity; /* no more parity evaluation, skip rest */
	}	    
	if (fbi==lbi) { /* we have found the bit error */
	    if (biconfmark) correct_bit(d2,fbi);
	    correct_bit(d,fbi);kb->correctederrors++;
	    lost_bits-=2; /* No initial parity, no outgoing */
	    kb->diffidx[i]=fbi+1; /* mark as emty */
	    goto skipparity; /* no more parity evaluation, skip rest */
	}
	mbi = fbi + (lbi - fbi +1)/2 - 1; /* new lower mid bitidx */
	fi=fbi/32; li=mbi/32; fm =firstmask(fbi&31); lm= lastmask(mbi&31); 
	if (fi==li) { /* in same word */
	    tmp_par = d[fi]&fm&lm;
	} else {
	    tmp_par = (d[fi]&fm) ^ (d[li]&lm);
	    for (ri=fi+1;ri<li;ri++) tmp_par ^=d[ri];
	} /* still need to parity tmp_par */
	if (((inh_data[i/32]&bt_mask(i))?1:0)==parity(tmp_par)) {
	    /* same parity, take upper half */
	    fbi=mbi+1; kb->diffidx[i]=fbi; /* update first bit idx */
	    matchresult |=1; /* indicate match with incoming parity */
	} else {
	    lbi=mbi; kb->diffidxe[i]=lbi; /* update last bit idx */
	}
	if (fbi==lbi) { /* end of interval, correct for error */
	    if (biconfmark) correct_bit(d2,fbi);
	    correct_bit(d,fbi); kb->correctederrors++;
	    lost_bits--; /* we don't reveal anything on this one anymore */
	    goto skipparity;
	}
	/* now, prepare new parity bit */
	mbi = fbi + (lbi - fbi +1)/2 - 1; /* new lower mid bitidx */
	fi=fbi/32; li=mbi/32; fm =firstmask(fbi&31); lm= lastmask(mbi&31);
	if (fi==li) { /* in same word */
	    tmp_par = d[fi]&fm&lm;
	} else {
	    tmp_par = (d[fi]&fm) ^ (d[li]&lm);
	    for (ri=fi+1;ri<li;ri++) tmp_par ^=d[ri];
	} /* still need to parity tmp_par */
	parityresult |= parity(tmp_par); /* save parity */
    skipparity:	
	if ((i&31) == 31) { /* save stuff in outbuffers */
	    out_match[i/32]=matchresult; out_parity[i/32]=parityresult;
	}
    }
    /* cleanup residual bit buffers */
    if (i & 31 ) { 
	out_match[i/32]  = matchresult  << (32-(i&31));
	out_parity[i/32] = parityresult << (32-(i&31));
    }

    /* a blocklength k decides on a max number of rounds */
    if ((kb->binsearch_depth & RUNLEVEL_ROUNDMASK ) <
	get_order_2((kb->processingstate==PRS_DOING_BICONF)?
		    (kb->biconflength):
		    (thispass?kb->k1:kb->k0))) {
	/* need to continue with this search; make packet 5 ready to send */
	kb->leakagebits += lost_bits;
	insert_sendpacket((char *)out_head, out_head->bytelength);
	return 0;
    }

    kb->leakagebits +=lost_bits; /* correction for unreceived parity bits and nonsent parities */
    
    /* cleanup changed bits in the other permuted field */
    fix_permutedbits(kb);
    
    /* prepare for alternate round; start with re-evaluation of parity. */
    while (1) { /* just a break construction.... */
	kb->binsearch_depth = thispass?RUNLEVEL_FIRSTPASS:RUNLEVEL_SECONDPASS;
	kb->diffnumber = 
	    do_paritylist_and_diffs(kb, 1-thispass); /* new differences */
	if (kb->diffnumber == -1) return 74; /* wrong pass */
	if ((kb->diffnumber==0) && (thispass ==1)) break; /* no more errors */
	if (kb->diffnumber>kb->diffnumber_max) { /* need more space */
	    free2(kb->diffidx);  /* re-assign diff buf */
	    kb->diffnumber_max = kb->diffnumber;
	    kb->diffidx=(unsigned int *)
		malloc2(kb->diffnumber*sizeof(unsigned int)*2);
	    if (!kb->diffidx) return 54; /* can't malloc */
	    kb->diffidxe = &kb->diffidx[kb->diffnumber]; /* end of interval */
	}
	
	/* do basically a start_binarysearch for next round */
	return prepare_first_binsearch_msg(kb,1-thispass); 
    }
    
    /* now we have finished a consecutive the second round; there are no more
       errors in both passes.  */

    /* check for biconf reply  */
    if (kb->processingstate==PRS_DOING_BICONF) { /* we are finally finished
					       with the BICONF corrections */
	/* update biconf status */
	kb->biconf_round++;
	
	/* eventully generate new biconf request */
	if (kb->biconf_round< biconf_rounds) {
	    return initiate_biconf(kb); /* request another one */
	}
	/* initiate the privacy amplificaton */
	return initiate_privacyamplification(kb);
    }

    /* we have no more errors in both passes, and we were not yet
       in BICONF mode */

    /* initiate the BICONF state */
    kb->processingstate = PRS_DOING_BICONF;
    kb->biconf_round = 0; /* first BICONF round */
    return initiate_biconf(kb);
}

/* ------------------------------------------------------------------------- */
/* function to process a binarysearch request. distinguishes between the two
   symmetries in the evaluation. This is onyl a wrapper.
   on alice side, it does a passive check; on bob side, it possibly corrects
   for errors. */

int process_binarysearch(char *receivebuf) {
    struct ERRC_ERRDET_5 *in_head; /* holds received message header */
    struct keyblock *kb; /* points to thread info */

    /* get pointers for header...*/
    in_head = (struct  ERRC_ERRDET_5 *)receivebuf;
    
    /* ...and find thread: */
    kb = get_thread(in_head->epoch);
    if (!kb) {
	fprintf(stderr,"binsearch 5 epoch %08x: ",in_head->epoch);
	return 49;
    }
    switch (kb->role) {
	case 0: /* alice, passive part in binsearch */
	    return process_binsearch_alice(kb,in_head);
	case 1: /* bob role; active part in binsearch */
	    return process_binsearch_bob(kb,in_head);
	default: return 56; /* illegal role */
    }
    return 0; /* keep compiler happy */
}
/* ------------------------------------------------------------------------ */
/* helper funtion to get a simple one-line parity from a large string.
   parameters are the string start buffer, a start and an enx index. returns
   0 or 1 */
int single_line_parity(unsigned int *d, int start, int end) {
    unsigned int tmp_par, lm, fm;
    int li, fi, ri;
    fi=start/32; li=end/32; lm=lastmask(end&31); fm = firstmask(start & 31);
    if (li==fi) {
	tmp_par=d[fi]&lm&fm;
    } else {
	tmp_par=(d[fi]&fm) ^ (d[li]&lm);
	for (ri=fi+1;ri<li;ri++) tmp_par ^= d[ri];
    } /* tmp_par holds now a combination of bits to be tested */
    return parity(tmp_par);
}

/* ------------------------------------------------------------------------ */
/* helper funtion to get a simple one-line parity from a large string, but
   this time with a mask buffer to be AND-ed on the string.
   parameters are the string buffer, mask buffer, a start and and end index.
   returns  0 or 1 */
int single_line_parity_masked(unsigned int *d, unsigned int *m,
			      int start, int end) {
    unsigned int tmp_par, lm, fm;
    int li, fi, ri;
    fi=start/32; li=end/32; lm=lastmask(end&31); fm = firstmask(start & 31);
    if (li==fi) {
	tmp_par=d[fi] & lm & fm & m[fi];
    } else {
	tmp_par=(d[fi] & fm & m[fi]) ^ (d[li] & lm & m[li]);
	for (ri=fi+1;ri<li;ri++) tmp_par ^= (d[ri] & m[ri]);
    } /* tmp_par holds now a combination of bits to be tested */
    return parity(tmp_par);
}

/* ------------------------------------------------------------------------- */
/* start the parity generation process on Alice side. parameter contains the
   input message. Reply is 0 on success, or an error message. Should create
   a BICONF response message */
int generate_biconfreply(char *receivebuf) {
    struct  ERRC_ERRDET_6 *in_head; /* holds received message header */
    struct  ERRC_ERRDET_7 *h7; /* holds response message header */
    struct keyblock *kb; /* points to thread info */
    int bitlen; /* number of bits requested */  

    /* get pointers for header...*/
    in_head = (struct  ERRC_ERRDET_6 *)receivebuf;
    
    /* ...and find thread: */
    kb = get_thread(in_head->epoch);
    if (!kb) {
	fprintf(stderr,"epoch %08x: ",in_head->epoch);
	return 49;
    }

    /* update thread status */
    switch (kb->processingstate) {
	case PRS_PERFORMEDPARITY1: /* just finished BICONF */
	    kb->processingstate= PRS_DOING_BICONF; /* update state */
	    kb->biconf_round=0; /* first round */
	    break;
	case PRS_DOING_BICONF: /* already did a biconf */
	    kb->biconf_round++; /* increment processing round; more checks? */
	    break;
    }
    /* extract number of bits and seed */
    bitlen = in_head->number_of_bits; /* do more checks? */
    kb->RNG_state = in_head->seed; /* check for 0?*/
    kb->biconflength = bitlen;

    /* prepare permutation list */
    /* old: prepare_permut_core(kb); */

    /* generate local (alice) version of test bit section */
    generate_BICONF_bitstring(kb); 
 
    
    /* fill the response header */
    h7=(struct ERRC_ERRDET_7 *) malloc2(sizeof(struct ERRC_ERRDET_7));
    if (!h7) return 61;
    h7->tag = ERRC_PROTO_tag; h7->bytelength=sizeof(struct ERRC_ERRDET_7);
    h7->subtype = ERRC_ERRDET_7_subtype; h7->epoch = kb->startepoch;
    h7->number_of_epochs = kb->numberofepochs;

    /* evaluate the parity (updated to use testbit buffer */
    h7->parity = single_line_parity(kb->testmarker,0,bitlen-1);

    /* update bitloss */
    kb->leakagebits++; /* one is lost */

    /* send out response header */
    insert_sendpacket((char *)h7, h7->bytelength);

    return 0;/* return nicely */
}
/* ------------------------------------------------------------------------- */
/* function to generate a single binary search request for a biconf cycle.
   takes a keyblock pointer and a length of the biconf block as a parameter,
   and returns an error or 0 on success.
   Takes currently the subset of the biconf subset and its complement, which
   is not very efficient: The second error could have been found using the
   unpermuted short sample with nuch less bits.
   On success, a binarysearch packet gets emitted with 2 list entries. */
int initiate_biconf_binarysearch(struct keyblock *kb, int biconflength) {
    unsigned int msg5size;        /* size of message */
    struct ERRC_ERRDET_5 *h5;     /* pointer to first message */
    unsigned int *h5_data, *h5_idx; /* data pointers */
 
    kb->diffnumber=1;
    kb->diffidx[0]=0; kb->diffidxe[0]=biconflength-1;
    
    /* obsolete: 
       kb->diffidx[1]=biconflength;kb->diffidxe[1]=kb->workbits-1; */

    kb->binsearch_depth = RUNLEVEL_SECONDPASS; /* only pass 1 */

    /* prepare message buffer for first binsearch message  */
    msg5size = sizeof(struct ERRC_ERRDET_5 ) /* header need */
	+ sizeof(unsigned int) /* parity data need */
	+ 2*sizeof(unsigned int); /* indexing need for selection and compl */
    h5 = (struct ERRC_ERRDET_5 *)malloc2(msg5size);
    if (!h5) return 55;
    h5_data = (unsigned int *) &h5[1]; /* start of data */
    h5->tag = ERRC_PROTO_tag; h5->subtype = ERRC_ERRDET_5_subtype;
    h5->bytelength = msg5size; h5->epoch = kb->startepoch;
    h5->number_of_epochs = kb->numberofepochs;
    h5->number_entries = kb->diffnumber;
    h5->index_present = 4; /* NEW this round we have a start/stop table */

    /* keep local status and indicate the BICONF round to Alice */
    h5->runlevel = kb->binsearch_depth | RUNLEVEL_BICONF;

    /* prepare block index list of simple type 1, uncompressed uint32 */
    h5_idx = &h5_data[1];
    /* for index mode 4: */
    h5_idx[0]=0; /* selected first bits */
    /* this information is IMPLICIT in the round 4 infromation and needs no
       transmission */
    /* h5_idx[2]=biconflength; h5_idx[3] = kb->workbits-biconflength-1;  */

    /* set parity */
    h5_data[0]=(single_line_parity(kb->testmarker, 0, biconflength/2-1)<<31);
    
    /* increment lost bits */
    kb->leakagebits +=1;

    /* send out message */
    insert_sendpacket((char *)h5, msg5size);

    return 0;
}


/* ------------------------------------------------------------------------- */
/* start the parity generation process on bob's side. Parameter contains the
   parity reply form Alice. Reply is 0 on success, or an error message.
   Should either initiate a binary search, re-issue a BICONF request or 
   continue to the parity evaluation. */
int receive_biconfreply(char *receivebuf){
    struct  ERRC_ERRDET_7 *in_head; /* holds received message header */
    struct keyblock *kb; /* points to thread info */
    int localparity;

    /* get pointers for header...*/
    in_head = (struct  ERRC_ERRDET_7 *)receivebuf;
    
    /* ...and find thread: */
    kb = get_thread(in_head->epoch);
    if (!kb) {
	fprintf(stderr,"epoch %08x: ",in_head->epoch);
	return 49;
    }
    
    kb->binsearch_depth=RUNLEVEL_SECONDPASS; /* use permuted buf */

    /* update incoming bit leakage */
    kb->leakagebits++;

    /* evaluate local parity */
    localparity= single_line_parity(kb->testmarker,0,kb->biconflength-1);

    /* eventually start binary search */
    if (localparity != in_head->parity) {
	return initiate_biconf_binarysearch(kb,kb->biconflength);
    }
    /* this location gets ONLY visited if there is no error in BICONF search */

    /* update biconf status */
    kb->biconf_round++;

    /* eventully generate new biconf request */
    if (kb->biconf_round< biconf_rounds) {
	return initiate_biconf(kb); /* request another one */
    }
    /* initiate the privacy amplificaton */
    return initiate_privacyamplification(kb);
}

/* ------------------------------------------------------------------------- */
/* helper function to dump the state of the system to a disk file . Dumps the 
   keyblock structure, if present the buffer files, the parity files and the
   diffidx buffers as plain binaries */
int dumpindex=0;
void dumpstate(struct keyblock *kb) {
    char dumpname[200];
    int dha; /* handle */

    return; /* if debugging is off */


    sprintf(dumpname,"kbdump_%1d_%03d",kb->role,dumpindex);
    dumpindex++;
    dha=open(dumpname,O_WRONLY | O_CREAT, 0644);
    write(dha,kb,sizeof(struct keyblock));
    if (kb->mainbuf) write(dha,kb->mainbuf,sizeof(unsigned int)*(
			       2*kb->initialbits+
			       3*((kb->initialbits+31)/32)));

    if (kb->lp0) write(dha,kb->lp0,sizeof(unsigned int)*
		       6*((kb->workbits+31)/32));

    if (kb->diffidx) write(dha,kb->diffidx,sizeof(unsigned int)*
			   2*kb->diffnumber_max);
    
    close(dha);
    return;
}
/* helper to dump message into a file */
int mdmpidx=0;
void dumpmsg(struct keyblock *kb, char *msg) {
    char dumpname[200];
    int dha; /* handle */
    int tosend = ((unsigned int *)msg)[1];
    int sent=0, retval;

    return; /* if debug is off */


    sprintf(dumpname,"msgdump_%1d_%03d",kb->role,mdmpidx);
    mdmpidx++;
    dha=open(dumpname,O_WRONLY | O_CREAT, 0644);
    do {
	retval=write(dha,msg, tosend-sent);
	if (retval==-1) {
	    fprintf(stderr, "cannot save msg\n");
	    exit(-1);
	}
	usleep(100000);
	sent +=retval;
    } while (tosend-sent>0);
    close(dha);
    return;
}
    
/*------------------------------------------------------------------------- */
/* process an input string, terminated with 0 */
int process_input(char *in) {
    int retval, retval2;
    unsigned int newepoch; /* command parser */
    int newepochnumber;
    float newesterror=0; /* for initial parsing of a block */
    float BellValue; /* for Ekert-type protocols */

    retval=sscanf(in,"%x %i %f %f",
		  &newepoch, &newepochnumber, &newesterror, &BellValue);
    printf("got cmd: epoch: %08x, num: %d, esterr: %f retval: %d\n",
	   newepoch, newepochnumber, newesterror, retval);
    switch (retval) {
	case 0: /* no conversion */
	    if (runtimeerrormode>0) break; /* nocomplain */
	    return -emsg(30); /* not enough arguments */
	case 1: /* no number and error */
	    newepochnumber=1;
	case 2: /* no error */
	    newesterror=initialerr;
	case 3: /* only error is supplied */
	    BellValue = 2.*sqrt(2.); /* assume perfect Bell */
	case 4: /* everything is there */
	    if (newesterror<0 || newesterror>MAX_INI_ERR) {
		if (runtimeerrormode>0) break;
			    return 31;
	    }
	    if (newepochnumber<1) {
		if (runtimeerrormode>0) break;
		return 32;
	    }
	    /* ok, we have a sensible command; check existing */
	    if (check_epochoverlap(newepoch, newepochnumber)) {
		if (runtimeerrormode>0) break;
		return 33;
	    }
	    /* create new thread */
	    if ((retval2=create_thread(newepoch,newepochnumber,
				       newesterror,BellValue))) {
		if (runtimeerrormode>0) break;
		return retval2; /* error reading files */
	    }
	    /* initiate first step of error estimation */
	    if ((retval2=errorest_1(newepoch))) {
		if (runtimeerrormode>0) break;
		return retval2; /* error initiating err est */
	    }
	    
	    printf("got a thread and will send msg1\n");
    }
    return 0;
}
/* ------------------------------------------------------------------------- */
/* main code */
int main (int argc, char *argv[]) {
    int opt;
    int i,noshutdown;
    struct stat cmdstat; /* for probing pipe */
    fd_set readqueue,writequeue; /* for main event loop */
    int retval, retval2;
    int selectmax; /* keeps largest handle for select call */
    struct timeval HALFSECOND = {0,500000};
    struct timeval TENMILLISEC = {0,10000};    
    struct timeval timeout; /* for select command */
    int send_index; /* for sending out packets */
    struct packet_to_send *tmp_packetpointer;
    int receive_index; /* for receiving packets */
    struct ERRC_PROTO msgprotobuf; /* for reading header of receive packet */
    char *tmpreadbuf=NULL; /* pointer to hold initial read buffer */
    struct packet_received *msgp; /* temporary storage of message header */
    struct packet_received *sbfp; /* index to go through the linked list */
    char instring[CMD_INBUFLEN]; /* for parsing commands */
    int ipt, sl;   /* cmd input variables */
    char *dpnt;  /* ditto */
    char *receivebuf;  /* pointer to the currently processed packet */
    float biconf_BER; /* to keep biconf argument */

    /* parsing parameters */
    opterr=0;
    while ((opt=getopt(argc, argv, "c:s:r:d:f:l:q:Q:e:E:kJ:T:V:Ipb:B:i"))!=EOF) {
	i=0; /* for paring filename-containing options */
	switch (opt) {
	    case 'V': /* verbosity parameter */
		if (1!=sscanf(optarg,"%d",&verbosity_level)) return -emsg(1);
		break;
	    case 'q': i++; /* respondpipe, idx=7 */
	    case 'Q': i++; /* querypipe, idx=6 */
	    case 'l': i++; /* notify pipe, idx=5 */
	    case 'f': i++; /* finalkeydir, idx=4 */
	    case 'd': i++; /* rawkeydir, idx=3 */
	    case 'r': i++; /* commreceivepipe, idx=2 */
	    case 's': i++; /* commsendpipe, idx=1 */
	    case 'c':      /* commandpipe, idx=0 */
		if (1!=sscanf(optarg,FNAMFORMAT,fname[i])) return -emsg(2+i);
		fname[i][FNAMELENGTH-1]=0;   /* security termination */
		break;
	    case 'e': /* read in error threshold */
		if (1!=sscanf(optarg,"%f",&errormargin)) return -emsg(10);
		if ((errormargin<MIN_ERR_MARGIN) || 
		    (errormargin>MAX_ERR_MARGIN)) return -emsg(11);
		break;
	    case 'E': /* expected error rate */
		if (1!=sscanf(optarg,"%f",&initialerr)) return -emsg(12);
		if ((initialerr<MIN_INI_ERR) || 
		    (initialerr>MAX_INI_ERR)) return -emsg(13);
		break;
	    case 'k': /* kill mode for raw files */
		killmode=1;
		break;
	    case 'J': /* error rate generated outside eavesdropper */
		if (1!=sscanf(optarg,"%f",&intrinsicerr)) return -emsg(14);
		if ((intrinsicerr<0) || 
		    (intrinsicerr>MAX_INTRINSIC)) return -emsg(15);
		break;
	    case 'T': /* runtime error behaviour */
		if (1!=sscanf(optarg,"%d",&runtimeerrormode)) return -emsg(16);
		if ((runtimeerrormode<0) || 
		    (runtimeerrormode>MAXRUNTIMEERROR)) return -emsg(16);
		break;
	    case 'I': /* skip initial error measurement */
		ini_err_skipmode=1;
		break; 
	    case 'i': /* expect a bell value for sneakage estimation */
		bellmode = 1;
		break;
	    case 'p': /* disable privacy amplification */
		disable_privacyamplification=1;
		break;
	    case 'b': /* set BICONF rounds */
		if (1!=sscanf(optarg,"%d",&biconf_rounds)) return -emsg(76);
		if ((biconf_rounds<=0 )|| (biconf_rounds>MAX_BICONF_ROUNDS ))
		    return -emsg(77);
		break;
	    case 'B': /* take BER argument to determine biconf rounds */
		if (1!=sscanf(optarg,"%f",&biconf_BER)) return -emsg(78);
		if ((biconf_BER<=0 ) || (biconf_BER>1 ))
		    return -emsg(79);
		biconf_rounds = (int)(-log(biconf_BER/AVG_BINSEARCH_ERR)/log(2));
		if (biconf_rounds<=0) biconf_rounds=1; /* at least one */
		if (biconf_rounds>MAX_BICONF_ROUNDS) return -emsg(77);
		printf("biconf rounds used: %d\n",biconf_rounds);
		break;
	}
    }
    /* checking parameter cosistency */
    for (i=0;i<8;i++) 
	if (fname[i][0]==0) 
	    return -emsg(17); /* all files and pipes specified ? */

    /* open pipelines */
    if (stat(fname[0],&cmdstat)) return -emsg(18);  /* command pipeline */
    if (!S_ISFIFO(cmdstat.st_mode)) return -emsg(19);
    if (!(fhandle[0]=fopen(fname[0],"r+"))) return -emsg(18);
    handle[0]=fileno(fhandle[0]);

    if (stat(fname[1],&cmdstat)) return -emsg(20);  /* send pipeline */
    if (!S_ISFIFO(cmdstat.st_mode)) return -emsg(21);
    if ((handle[1]=open(fname[1],FIFOOUTMODE))==-1) return -emsg(20);

    if (stat(fname[2],&cmdstat)) return -emsg(22);  /* receive pipeline */
    if (!S_ISFIFO(cmdstat.st_mode)) return -emsg(23);
    if ((handle[2]=open(fname[2],FIFOINMODE))==-1) return -emsg(22);

    if (!(fhandle[5]=fopen(fname[5],"w+"))) 
	return -emsg(24); /* notify pipeline */
    handle[5]=fileno(fhandle[5]);

    if (stat(fname[6],&cmdstat)) return -emsg(25);  /* query pipeline */
    if (!S_ISFIFO(cmdstat.st_mode)) return -emsg(26);
    if (!(fhandle[6]=fopen(fname[6],"r+"))) return -emsg(25);
    handle[6]=fileno(fhandle[6]);
    
    if (!(fhandle[7]=fopen(fname[7],"w+")))
	return -emsg(27); /* query response pipe */
    handle[7]=fileno(fhandle[7]);

    /* find largest handle for select call */
    handle[3]=0;handle[4]=0;selectmax=0;
    for (i=0;i<8;i++) if (selectmax<handle[i]) selectmax=handle[i];
    selectmax+=1;

    /* initializing buffers */
    next_packet_to_send = NULL; /* no packets to be sent */
    last_packet_to_send = NULL;
    send_index=0; /* index of next packet to send */
    receive_index=0; /* index for reading in a longer packet */
    blocklist=NULL;   /* no active key blocks in memory */
    rec_packetlist=NULL; /* no receive packet s in queue */

    /* main loop */
    noshutdown=1; /* keep thing running */
    instring[0]=0; ipt=0; /* input parsing */
    do {
	/* prepare select call */
	FD_ZERO(&readqueue);FD_ZERO(&writequeue);
	FD_SET(handle[6],&readqueue); /* query pipe */
	FD_SET(handle[2],&readqueue); /* receive pipe */
	FD_SET(handle[0],&readqueue); /* command pipe */
	if (next_packet_to_send || send_index )
	    FD_SET(handle[1],&writequeue); /* content to send */
	/* keep timeout short if there is work to do */
	timeout=((instring[0]||rec_packetlist)?TENMILLISEC:HALFSECOND);
	retval=select(selectmax,&readqueue,&writequeue,(fd_set *)0,&timeout);
	
	if (retval==-1) return -emsg(28);
	if (retval) { /* there was a pending request */
	    /*  handle send pipelne */
	    if (FD_ISSET(handle[1],&writequeue)) {
		i=next_packet_to_send->length-send_index;
		retval=write(handle[1],
			     &next_packet_to_send->packet[send_index],i);
		if (retval==-1) return -emsg(29);
		if (retval==i) { /* packet is sent */
		    free2(next_packet_to_send->packet);
		    tmp_packetpointer=next_packet_to_send;
		    next_packet_to_send=next_packet_to_send->next;
		    if (last_packet_to_send==tmp_packetpointer) 
			last_packet_to_send=NULL;
		    free2(tmp_packetpointer); /* remove packet pointer */
		    send_index=0; /* not digesting packet anymore */
		} else {
		    send_index+=retval;
		}
	    }
	    /*  poll cmd input */
	    if (FD_ISSET(handle[0],&readqueue)) {
		retval=read(handle[0],&instring[ipt],CMD_INBUFLEN-1-ipt);
		if (retval<0) break;
		ipt +=retval;instring[ipt]=0;
		if (ipt >= CMD_INBUFLEN) return -emsg(75); /* overflow */
		/* parse later... */
	    }
	    /* parse input string */
	    dpnt=index(instring,'\n');
	    if (dpnt) { /* we got a newline */
		dpnt[0]=0;sl=strlen(instring);
		retval2=process_input(instring);
		if (retval2&&(runtimeerrormode==0)){
		    return -emsg(retval2); /* complain */
		}
		/* move back rest */
		for (i=0;i<ipt-sl-1;i++) instring[i]=dpnt[i+1];
		ipt -=sl+1;instring[ipt]=0; /* repair index */
	    }
	    /*  poll receive pipeline */
	    if (FD_ISSET(handle[2],&readqueue)) {
		if (receive_index<sizeof(struct ERRC_PROTO)) {
		    retval=read(handle[2],
				&((char *)&msgprotobuf)[receive_index],
				sizeof(msgprotobuf)-receive_index);
		    if (retval==-1) return -emsg(36); /* can that be better? */
		    receive_index+=retval;
		    if (receive_index==sizeof(msgprotobuf)) {
			/* prepare for new buffer */
			tmpreadbuf=(char *)malloc2(msgprotobuf.bytelength);
			if (!tmpreadbuf) return -emsg(37);
			/* transfer header */
			memcpy(tmpreadbuf,&msgprotobuf,
			       sizeof(msgprotobuf));
		    }
		} else { /* we are reading the main message now */
		    retval=read(handle[2],&tmpreadbuf[receive_index],
				msgprotobuf.bytelength-receive_index);
		    if (retval==-1) return -emsg(36); /* can that be better? */
		    receive_index+=retval;
		    if (receive_index==msgprotobuf.bytelength) { /* got all */
			msgp=(struct packet_received *)
			    malloc2(sizeof(struct packet_received));
			if (!msgp) return -emsg(38);
			/* insert message in message chain */
			msgp->next=NULL;
			msgp->length=receive_index;
			msgp->packet=tmpreadbuf;
			sbfp = rec_packetlist;
			if (sbfp) {
			    while (sbfp->next) sbfp=sbfp->next;
			    sbfp->next=msgp;
			} else {
			    rec_packetlist=msgp;
			}
			receive_index=0; /* ready for next one */
		    }
		}
	    }
	    /*  check query pipeline */
	    if (FD_ISSET(handle[6],&readqueue)) {
		
	    }
	    
	}
	/* enter working routines for packets here */
	if ((sbfp=rec_packetlist)) { /* got one message */
	    receivebuf = sbfp->packet; /* get pointer */
	    if ( ((unsigned int *)receivebuf)[0] != ERRC_PROTO_tag) {
		return -emsg(44);
	    }
	    /* printf("received message, subtype: %d, len: %d\n",
		   ((unsigned int *)receivebuf)[2],
		   ((unsigned int *)receivebuf)[1]);fflush(stdout); */
    
	    switch (((unsigned int *)receivebuf)[2]) { /* subtype */
		case 0: /* received an error estimation packet */
		    retval=process_esti_message_0(receivebuf);
		    if (retval) { /* an error occured */
			if (runtimeerrormode>1) break;
			return -emsg(retval);
		    }
		    break;
		case 2: /* received request for more bits */
		    retval=send_more_esti_bits(receivebuf);
		    if (retval) { /* an error occured */
			if (runtimeerrormode>1) break;
			return -emsg(retval);
		    }

		    break;
		case 3: /* reveived error confirmation message */
		    retval=prepare_dualpass(receivebuf);
		    if (retval) { /* an error occured */
			if (runtimeerrormode>1) break;
			return -emsg(retval);
		    }
		    break;
		case 4: /* reveived parity list message */
		    retval=start_binarysearch(receivebuf);
		    if (retval) { /* an error occured */
			if (runtimeerrormode>1) break;
			return -emsg(retval);
		    }
		    break;
		case 5: /* reveive a binarysearch message */
		    retval=process_binarysearch(receivebuf);
		    if (retval) { /* an error occured */
			if (runtimeerrormode>1) break;
			return -emsg(retval);
		    }

		    break;
		case 6: /* receive a BICONF initiating request */
		    retval=generate_biconfreply(receivebuf);
		    if (retval) { /* an error occured */
			if (runtimeerrormode>1) break;
			return -emsg(retval);
		    }

		    break;
		case 7: /* receive a BICONF parity response */
		    retval=receive_biconfreply(receivebuf);
		    if (retval) { /* an error occured */
			if (runtimeerrormode>1) break;
			return -emsg(retval);
		    }

		    break;
		case 8: /* receive a privacy amplification start msg */
		    retval=receive_privamp_msg(receivebuf);
		    if (retval) { /* an error occured */
			if (runtimeerrormode>1) break;
			return -emsg(retval);
		    }
		    break;
		    
		default: /* packet subtype not known */
		    fprintf(stderr,"received subtype %d; ",
			    ((unsigned int *)receivebuf)[2]);
		    return -emsg(45);
	    }
	    /* printf("receive packet successfully digested\n");
	       fflush(stdout); */
	    /* remove this packet from the queue */
	    rec_packetlist = sbfp->next; /* upate packet pointer */
	    free2(receivebuf); /* free data section... */
	    free2(sbfp); /* ...and pointer entry */
	}

    } while (noshutdown);
    /* close nicely */
    fclose(fhandle[0]);close(handle[1]);close(handle[2]);
    fclose(fhandle[5]);fclose(fhandle[6]);fclose(fhandle[7]);
    return 0;
}
