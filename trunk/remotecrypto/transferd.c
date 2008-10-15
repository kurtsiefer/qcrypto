/* transferd.c : Part of the quantum key distribution software for serving
                 as a classical communication gateway between the two sides.
		 Description see below. Version as of 20070101

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


   program to arrange for file transfer from one machine to the other. This is
   taking care of the sockets between two machines. Each machine has a version
   of it running. This deamon listens to a command port for file names to be
   transferred, which are specified relative to a initially agreed directory,
   and transmitts the underlying file to the other side. On the receiving side,
   files are saved in a directory, and a notofication is placed in a file.

   status: worked on more than 55k epochs on feb 7 06
   tried to fix some errcd packet errors 30.4.06chk

 usage: transferd -d sourcedirectory -c commandsocket -t targetmachine
                  -D destinationdir -l notificationfile -s sourceIP
		  [-e ec_in_pipe -E ec_out_pipe ]
		  [-k] 
		  [-m messagesource -M messagedestintion ]
		  [-p portnumber]
		  [-v verbosity]

 parameters:
  
  -d srcdir:        source directory for files to be transferred
  -c commandpipe:   where to create a fifo in the file system to
                    listen to files to be transferred. the path has to be
		    absolute.
  -t target:        IP address of target machine
  -D destdir:       destination directory
  -l notify:        if a packet arrives and has been saved, a notification
                    (the file name itself) is sent to the file or pipe named
		    in the parameter of this option
  -s sourceIP:      listen to connections on the local ip identified by the
                    paremeter. By default, the system listens on all ip
		    addresses of the machine.
  -k:               killoption. If this is activated, a file gets destroyed in
                    the source directory after it has been sent.
  -m src:           message source pipe. this opens a local fifo in the file
                    tree where commands can be tunneled over to the other side.
  -M dest:          if a command message is sent in from the other side, it
                    will be transferred into the file or pipe named in the
		    parameter of this file.
  -p portnum:       port number used for communication. By default, this is
                    port number 4852.
  -v verbosity:     choose verbosity. 0: no normal output to stdout
                    1: connect/disconnect to stdout
		    2: talk about receive/send events
		    3: include file error events
  -e ec_in_pipe:    pipe for receiving packets from errorcorrecting demon
  -E ec_out_pipe:   pipe to send packes to the error correcting deamon

		    
  momentarily, the communication is implemented via tcp/ip packets. the program
  acts either as a server or a client, depending on the status of the other
  side.  if client mode fails, it goes into server mode. if no connection is
  available within a few seconds, it tries to connect to the client again.

  Transfer rationale: The same channel will be used for messages, files and
  error correction packets. Since there is no simple way to extract the length
  of the file for all possible future extensions, the transmission of whatever
  is preceeded by a header involving a 
     typedef struct stream_header {int type;
                                   unsigned int length; };
  were type is 0 for simple files, 1 for messages, 2 for errc packets and
  length designates the
  length of the data in bytes. In a later stage, the messages might be sent via
  an out-of-band marker, but this is currently not implemented. 

History: first test seems to work 6.9.05chk
  stable version 16.9. started modifying for errorcorrecting packets
  modified for closing many open files feb4 06 chk

To Do:
- use udp protocol instead of tcp, and/or allow for setting more robust
  comm options.
- check messaging system ok, but what happens with emty messages?
- allow for other file types - added another port....
- clean up debugging code 

*/
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/select.h>

#undef DEBUG

extern int h_errno;

/* default definitions */
#define DEFAULT_KILLMODE 0   /* don't remove files after sending */
#define FNAMELENGTH 200  /* length of file name buffers */
#define FNAMFORMAT "%199s"   /* for sscanf of filenames */
#define tmpfileext "/tmprec" /* temporary receive file */
#define DEFAULT_PORT 4852  /* standard communication */
#define MINPORT 1024      /* port boundaries */
#define MAXPORT 60000
#define RECEIVE_BACKLOG 2 /* waiting requests on remote queue */
#define MSG_BACKLOG 10 /* waiting requests */
#define LOC_BUFSIZE 1<<22 /* 512k buffer should last for a file */
#define LOC_BUFSIZE2 10000 /* 10k buffer for errc messages */
#define TARGETFILEMODE (O_WRONLY | O_TRUNC | O_CREAT)
#define FILE_PERMISSIONS 0644  /* for all output files */
#define READFILEMODE O_RDONLY
#define MESSAGELENGTH 1024 /* message length */
#define FIFOPERMISSIONS 0600 /* only user can access */
#define FIFOMODE O_RDONLY | O_NONBLOCK
#define FIFOOUTMODE O_RDWR
#define DUMMYMODE O_WRONLY 
#define DEFAULT_IGNOREFILEERROR 1
#define DEFAULT_VERBOSITY 1

/* stream header definition */
typedef struct stream_header {int type; /* 0: ordinary file, 1: message */
    unsigned int length; /* len in bytes */
    unsigned int epoch;} sh;

/* errorcorrecting packet header def */
typedef struct errc_header { int tag;
    unsigned int length; } eh;

/* global variables for IO handling */
char fname[10][FNAMELENGTH]={"","","","","","","","","",""}; /* stream files */
char ffnam[10][FNAMELENGTH+10], ffn2[FNAMELENGTH+10];
char f3tmpname [FNAMELENGTH+10]; /* stores temporary file name */
int killmode = DEFAULT_KILLMODE; /* if !=1, delete infile after use */
int handle[10]; /* global handles for packet streams */
FILE *debuglog;


/* error handling */
char *errormessage[76] = {
  "No error.",
  "error parsing source directory name", /* 1 */
  "error parsing command socket name",
  "error parsing target machine name",
  "error parsing destination directory name",
  "error parsing notification destination name", /* 5 */
  "error parsing remote server socket name",
  "error parsing message source pipe",
  "error parsing message destination file/pipe",
  "error parsing errorcorrection instream pipe",
  "error parsing errorcorrection outstream pipe",  /* 10 */
  "cannot create errc_in pipe",
  "cannot open errc_in pipe",
  "cannot create errc_out pipe",
  "cannot open errc_out pipe",
  "no consistent message pipline definition (must have both)", /* 15 */
  "cannot create socket",
  "cannot create command FIFO",
  "cannot open command FIFO ",
  "cannot create message FIFO",
  "cannot open message FIFO",  /* 20 */
  "target host not found",
  "valid target name has no IP",
  "temporary IP resolve error. Try later",
  "unspecified target host resolve error.",
  "invalid local IP", /* 25 */
  "error in binding socket",
  "cannot stat source directory",
  "specified source is not a directory",
  "cannot stat target directory",
  "specified target dir is not a directory", /* 30 */
  "error reading command",
  "cannot listen on incoming request socket",
  "Error from waiting for server connections",
  "unlogical return fromselect",
  " ; error accepting connection", /* 35 */
  " ; error in connecting to peer",
  "getsockopt failed.",
  " ; socket error occured.",
  "select on input lines failed w error.",
  "Error reading stream header form external source.", /* 40 */
  "cannot malloc send/receive buffers.",
  "error reading stream data",
  "cannot open target file",
  "cannot write stream to file",
  "cannot open message target", /* 45 */
  "cannot write message into local target",
  "received message but no local message target specified",
  "unexpected data type received", 
  "cannot open notofication target",
  "cannot stat source file", /* 50 */
  "source is not a regular file",
  "cannot extract epoch from filename",
  "cannot open source file",
  "length read mismatch from source file",
  "Cannot send header", /* 55 */
  "cannot sent data stream",
  "cannot read message",
  "message too long",
  "received message longer than buffer.",
  "transferred larger than buffer", /* 60 */
  "socket probably closed.",
  "reached end of command pipe??????",
  "cannot remove source file."
  "cannot set reuseaddr socket option",
  "error parsing port number", /* 65 */
  "port number out of range",
  "no source directory specified",
  "no commandsocket name specified",
  "no target url specified",
  "no destination directory specified", /* 70 */
  "no arrival notify destination specified",
  "Error reading stream header form errc source.",
  "received packet longer than erc buffer.",
  "error reading erc packet",
  "error renaming target file", /* 75 */
};

int emsg(int code) {
  fprintf(stderr,"%s\n",errormessage[code]);
 
   fprintf(debuglog,"err msg: %s\n",errormessage[code]);
   fflush(debuglog);

  return code;
};

/* global variables for IO handling */

/* some helpers */
#define MIN(A,B) ((A)>(B)?(B):(A))

struct timeval HALFSECOND = {0,50000};
/* helper for name. adds a slash, hex file name and a termial 0 */
char hexdigits[]="0123456789abcdef";
void atohex(char* target,unsigned int v) {
    int i;
    target[0]='/';
    for (i=1;i<9;i++) target[i]=hexdigits[(v>>(32-i*4)) & 15];
    target[9]=0;
}

int main(int argc, char *argv[]) {
    int verbosity = DEFAULT_VERBOSITY;
    int opt,i,ii,retval; /* general parameters */
    int typemode[10]={0,0,0,0,0,0,0,0,0,0};
    /* sockets and destination structures */
    int sendskt,recskt,commskt;
    FILE *cmdhandle;
    int portnumber=DEFAULT_PORT; /* defines communication port */
    int msginhandle=0;
    int ercinhandle=0,ercouthandle=0; /* error correction pipes */
    unsigned int sendsktlen,remotelen;
    struct sockaddr_in sendadr,recadr,remoteadr;
    struct hostent *remoteinfo; 
    /* file handles */
    int srcfile, destfile;
    FILE *loghandle, *msgouthandle;
    struct stat dirstat; /* for checking directories */
    struct stat srcfilestat;
    fd_set readqueue,writequeue;
    struct timeval timeout; /* for select command */
    struct stream_header shead; /* for sending */
    struct stream_header rhead; /* for receiving */
    char *recbf,*filebf, *ercbf; /* send- and receive buffers, ercin buffer */
    char *sendbf; /* for write procedure */
    char transfername[FNAMELENGTH]; /* read transfer file name */
    char ftnam[FNAMELENGTH]; /* full transfer file name */
    unsigned int srcepoch;
    unsigned oldsrcepoch = 0;
    int receivemode;   /* for filling input buffer */
    unsigned int  receiveindex; 
    int packinmode; /* for reading errc packets from pipe */
    unsigned int erci_idx=0; /* initialize to keep compiler happy */
    struct errc_header *ehead; /* for reading packets */
    /* flags for select mechanism */
    int writemode, writeindex,cmdmode,messagemode;
    char message[MESSAGELENGTH];
    /* int keepawake_handle; */
    int keepawake_h2; /* avoid the input pipe seeing EOF */
    int keepawake_h3;
    int ignorefileerror=DEFAULT_IGNOREFILEERROR;
    int noshutdown;
    FILE *cmdinhandle;
    
    /* parsing options */
    opterr=0; /* be quiet when there are no options */
    while ((opt=getopt(argc, argv, "d:c:t:D:l:s:km:M:p:e:E:")) != EOF) {
	i=0; /* for setinf names/modes commonly */
	switch (opt) {
	    case 'E': i++;
	    case 'e': i++;
	    case 'M': i++; /* funky way of saving file names */
	    case 'm': i++;
	    case 's': i++;
	    case 'l': i++;
	    case 'D': i++;
	    case 't': i++;
	    case 'c': i++;
	    case 'd':
		 /* stream number is in i now */
		if (1!=sscanf(optarg,FNAMFORMAT,fname[i])) return -emsg(1+i);
		fname[i][FNAMELENGTH-1]=0;   /* security termination */
		if (typemode[i]) return -emsg(1+i); /* already defined mode */
		typemode[i]=1;
		break;
	    case 'k': /* killmode */
		killmode=1;
		break;
	    case 'p': /* set portnumber */
		if (sscanf(optarg,"%d",&portnumber)!=1) return -emsg(65);
		if ((portnumber<MINPORT) || (portnumber>MAXPORT)) return -emsg(66);
		break;
	}
    }

    /* check argument completeness */
    for (i=0;i<5;i++) if (typemode[i]==0 ) return -emsg(i+67);
    if (typemode[6]!=typemode[7]) return -emsg(15); /* not same message mode */
    /* add directory slash for sourcefile if missing */
    if (fname[0][strlen(fname[0])-1]!='/') {
	strncat(fname[0],"/",FNAMELENGTH);
	fname[0][FNAMELENGTH-1]=0;
    }
    cmdinhandle=fopen("/tmp/cryptostuff/cmdins","w+");


    debuglog=fopen("/tmp/cryptostuff/debuglog","w+");


    /* get all sockets */
    sendskt=socket(AF_INET,SOCK_STREAM,0); /* outgoing packets */
    recskt=socket(AF_INET,SOCK_STREAM,0); /* incoming packets */
    if (!sendskt || !recskt) return -emsg(16);
   
    /* command pipe */
    if (access(fname[1],F_OK)==-1) { /* fifo does not exist */
	if (mkfifo(fname[1],FIFOPERMISSIONS)) return -emsg(17);
    }
   
    cmdhandle=fopen(fname[1],"r+");
    if (!cmdhandle) return -emsg(18);
    /*cmdhandle=open(fname[1],FIFOMODE);
    if (cmdhandle==-1) return -emsg(18);
    keepawake_handle= open(fname[1],DUMMYMODE); */ /* keep server alive */

   /* message pipe */
    if (typemode[6]) { /* message pipes exist */
	if (access(fname[6],F_OK)==-1) { /* fifo does not exist */
	    if (mkfifo(fname[6],FIFOPERMISSIONS)) return -emsg(19);
	}
	msginhandle= open(fname[6],FIFOMODE);
	if (msginhandle==-1) return -emsg(20); /* cannot open FIFO */
	keepawake_h2=open(fname[6],DUMMYMODE); /* avoid message congestion */

    };

    /* errc_in pipe */
    if (typemode[8]) { /* listen to it */
	if (access(fname[8],F_OK)==-1) { /* fifo does not exist */
	    if (mkfifo(fname[8],FIFOPERMISSIONS)) return -emsg(11);
	}
	ercinhandle= open(fname[8],FIFOMODE);
	if (ercinhandle==-1) return -emsg(12); /* cannot open FIFO */
	keepawake_h3=open(fname[8],DUMMYMODE); /* avoid message congestion */
    };
    /* errc_out pipe */
    if (typemode[9]) { /* open it */
	if (access(fname[9],F_OK)==-1) { /* fifo does not exist */
	    if (mkfifo(fname[9],FIFOPERMISSIONS)) return -emsg(13);
	}
	ercouthandle= open(fname[9],FIFOOUTMODE);
	if (ercouthandle==-1) return -emsg(14); /* cannot open FIFO */
    };

    /* client socket for sending data */
    sendsktlen=strlen(fname[2]);
    sendadr.sin_family = AF_INET;
    remoteinfo=gethostbyname(fname[2]);
    if (!remoteinfo) {
	switch(h_errno) {
	    case HOST_NOT_FOUND: return -emsg(21);
	    case NO_ADDRESS: return -emsg(22);
	    case TRY_AGAIN: return -emsg(23);
	    default: return -emsg(24);
	}}
    /* extract host-IP */
    sendadr.sin_addr=*(struct in_addr *)*remoteinfo->h_addr_list;
    sendadr.sin_port=htons(portnumber);

    /* create socket for server / receiving files */
    recadr.sin_family=AF_INET;
    if (fname[5][0]) { /* port defined */
	if (inet_aton(fname[5],&recadr.sin_addr))
	    return -emsg(25);
    } else {
	recadr.sin_addr.s_addr=htonl(INADDR_ANY);
    }
    recadr.sin_port=htons(portnumber);
    /* try to reuse address */
    i=1;
    retval=setsockopt(recskt,SOL_SOCKET,SO_REUSEADDR,&i,sizeof(i));
    if (retval==-1) return -emsg(64);
    if (bind(recskt,(struct sockaddr *)&recadr,sizeof(recadr))) {
	switch (errno) {/* gove perhaps some specific errors */
	    default: 
		fprintf(stderr,"error in bind: %d\n",errno);
		return -emsg(26);

	}
    }
    if (listen(recskt,RECEIVE_BACKLOG)) return -emsg(32);

    /* try to test directory existence */
    if (stat(fname[0],&dirstat)) return -emsg(27); /* src directory */
    if ((dirstat.st_mode & S_IFMT)!=S_IFDIR) return -emsg(28); /* no dir */

    if (stat(fname[3],&dirstat)) return -emsg(29); /* src directory */
    if ((dirstat.st_mode & S_IFMT)!=S_IFDIR) return -emsg(30); /* no dir */ 

    /* try to get send/receive buffers */
    filebf=(char *)malloc(LOC_BUFSIZE);
    recbf=(char *)malloc(LOC_BUFSIZE);
    ercbf=(char *)malloc(LOC_BUFSIZE2);
    if (!filebf || !recbf || !ercbf ) return -emsg(41);
    ehead = (struct errc_header*)ercbf; /* for header */

    /* prepare file name for temporary file storage */
    strncpy(f3tmpname,fname[3],FNAMELENGTH);
    strcpy(&f3tmpname[strlen(f3tmpname)],tmpfileext);

    
    /* prepare shutdown */
    noshutdown=1;

    do { /* while link should be maintained */
	commskt=0; /* mark unsuccessful connection attempt */
	/* wait half a second for a server connection */
	FD_ZERO(&readqueue);timeout=HALFSECOND;
	FD_SET(recskt,&readqueue);
	retval=select(FD_SETSIZE,&readqueue,(fd_set *)0,(fd_set *)0,&timeout);
	if (retval==-1) return -emsg(33);
	if (retval) { /* there is a request */
	    if (!FD_ISSET(recskt,&readqueue)) return -emsg(34); /* cannot be?*/
	    /* accept connection */
	    remotelen=sizeof(remoteadr);
	    retval=accept(recskt,(struct sockaddr *)&remoteadr,&remotelen);
	    if (retval<0) {
		fprintf(stderr,"Errno: %d ",errno);
		return -emsg(35);
	    }
	    /* use new socket */
	    commskt=retval;
	} else { /* timeout has occured. attempt to make client connection */
	    fcntl(sendskt,F_SETFL,O_NONBLOCK); /* prepare nonblock mode */
	    retval=connect(sendskt,(struct sockaddr *)&sendadr,
			   sizeof(sendadr));
	    /* check for anythinng else than EINPROGRESS */
	    if (retval) { /* an error has occured */
		if ((errno==EALREADY) || (errno==ECONNABORTED)){
		    continue; /* trying already...*/
		}
		if (errno !=EINPROGRESS) {
		    if (errno == ETIMEDOUT) continue;
		    fprintf(stderr,"errno: %d",errno);
		    return -emsg(36);
		} else {
		    /* wait half a second for response of connecting */
		    FD_ZERO(&writequeue); FD_SET(sendskt,&writequeue);
		    timeout=HALFSECOND;
		    retval=select(FD_SETSIZE,(fd_set *)0,
				  &writequeue,(fd_set *)0,&timeout);
		    if (retval) {
			i=sizeof(retval);
			if (getsockopt(sendskt, SOL_SOCKET,
				       SO_ERROR,&retval,&i)) return -emsg(38);
			if (retval) {
			    /* printf("point2e\n"); */
			    if (errno==EINPROGRESS) continue;
			    fprintf(stderr,"errno: %d",errno);
			    return -emsg(38);
			}
			/* Weee! we succeeded geting a connection */
			commskt=sendskt;

		    } else { /* a timeout has occured */
			commskt=0;
		    }
		}
	    } else { /* it worked in the first place */
		commskt=sendskt;
	    }
	}

	if (commskt) if (verbosity>0) {
	    printf("connected.\n");
	    fflush(stdout);
	}

	receivemode=0;  /* wait for a header */
	receiveindex=0;
	writemode=0;writeindex=0;sendbf=NULL;
	packinmode=0; /* waiting for header */
	cmdmode=0;messagemode=0; /* finish eah thing */
	while (commskt) { /* link is active,  wait on input sockets */
	    FD_ZERO(&readqueue); FD_ZERO(&writequeue);
	    FD_SET(commskt,&readqueue); 
	    if (!cmdmode) FD_SET(fileno(cmdhandle),&readqueue);
	    if (sendbf) FD_SET(commskt,&writequeue); /* if we need to write */
	    if (typemode[6] && !messagemode) FD_SET(msginhandle,&readqueue);
	    if (typemode[8] && (packinmode!=4)) FD_SET(ercinhandle,&readqueue);
	    timeout=HALFSECOND;
	    retval=select(FD_SETSIZE,&readqueue,&writequeue,NULL,NULL);
	    if (retval<0) return -emsg(39);
	    /* eat through set */
#ifdef DEBUG
	    fprintf(debuglog,"select returned %d\n",retval);fflush(debuglog);
#endif
	    if (FD_ISSET(commskt,&readqueue)) { /* something's coming... */
#ifdef DEBUG
		fprintf(debuglog,"tcp read received event\n");
#endif
		switch (receivemode) {
		    case 0: /* beginning with header */
			receivemode=1;
		    case 1: /* finishing header */
			retval=read(commskt,&((char *)&rhead)[receiveindex],
				    sizeof(rhead)-receiveindex);
#ifdef DEBUG
			fprintf(debuglog,"tcp receive stage 1:%d bytes\n",retval);fflush(debuglog);
#endif
			if (retval==0) { /* end of file, peer terminated */
			    receivemode=0;
			    goto reconnect;
			    break;
			}
			if (retval==-1) {
			    if (errno==EAGAIN) break;
			    fprintf(stderr,"errno: %d ",errno);
#ifdef DEBUG
			    fprintf(debuglog,"error st1: %d\n",errno);
			    fflush(debuglog);
#endif
			    return -emsg(40);
			}
#ifdef DEBUG
			fprintf(debuglog,"p3\n");fflush(debuglog);
#endif
			receiveindex+=retval;
			if (receiveindex<sizeof(rhead)) break;
#ifdef DEBUG
			fprintf(debuglog,"p4, len:%d\n",rhead.length);
			for (i=0;i<12;i++) fprintf(debuglog,"%02x ",((unsigned char *)&rhead)[i]);fprintf(debuglog,"\n");
			fflush(debuglog);
#endif
		        /* got header, start reading data */
			if (rhead.length > LOC_BUFSIZE) return -emsg(59);
			receiveindex=0;receivemode=3;
#ifdef DEBUG
			fprintf(debuglog,"tcp receive before stage3, expect %d bytes\n",rhead.length);
			fflush(debuglog);
#endif
			break;
		    case 3: /* read more */
			retval=read(commskt,&recbf[receiveindex],
				  MIN(LOC_BUFSIZE,rhead.length)-receiveindex);
#ifdef DEBUG
			fprintf(debuglog,"tcp rec stage 3:%d bytes, wanted:%d\n",retval,MIN(LOC_BUFSIZE,rhead.length)-receiveindex);fflush(debuglog);
#endif
			if (retval==-1) {
			    if (errno==EAGAIN) break;
			    fprintf(stderr,"errno: %d ",errno);
#ifdef DEBUG
			    fprintf(debuglog,"errno (read, stag3): %d",errno);
			    fflush(debuglog);
#endif
			    if (errno==ECONNRESET) goto reconnect;
			    return -emsg(42);}
			receiveindex+=retval;
			if (receiveindex>=rhead.length) {
			    receivemode=4; /* done */
#ifdef DEBUG
			    fprintf(debuglog,"tcp receive stage 4 reached\n");fflush(debuglog);
#endif
			}
			break;
		}
		if (receivemode==4) { /* stream read complete */
		    switch(rhead.type) {
			case 0: /* incoming long stream */
			    /*if (verbosity >1) */
#ifdef DEBUG
			    fprintf(debuglog,"got file via tcp, len:%d\n",
				    rhead.length);fflush(debuglog);
#endif
			    /* open target file */
			    strncpy(ffnam[3],fname[3],FNAMELENGTH);
			    atohex(&ffnam[3][strlen(ffnam[3])],rhead.epoch);
			    destfile=
				open(f3tmpname,TARGETFILEMODE,FILE_PERMISSIONS);
			    if (destfile<0) {
				   fprintf(debuglog,"destfile  val: %x\n",destfile);
				   fprintf(debuglog,"file name: %s, len: %d\n",
					   ffnam[3], rhead.length);
				   fprintf(debuglog,"errno on opening: %d\n",errno);
				   fflush(debuglog);
				   destfile=open("transferdump",O_WRONLY);
				   if (destfile!=-1) {
				       write(destfile,recbf,rhead.length);
				       close(destfile);
				   }
				   return -emsg(43);
			    }
			    if ((int)rhead.length!=write(destfile,recbf,rhead.length))
				return -emsg(44);
			    close(destfile);
			    /* rename file */
			    if (rename(f3tmpname,ffnam[3])) {
				fprintf(stderr,"rename errno: %d ",errno);
				return -emsg(75);
			    }
			    /* send notification */
			    loghandle=fopen(fname[4],"a");
			    if (!loghandle) return -emsg(49);
			    fprintf(loghandle,"%08x\n",rhead.epoch);
			    fflush(loghandle);
			    fclose(loghandle);
#ifdef DEBUG
			    fprintf(debuglog,"sent notif on file %08x\n",rhead.epoch);fflush(debuglog);
#endif
			    break;
			case 1: /* incoming message */
			    /* if (verbosity>1) */
#ifdef DEBUG
			    fprintf(debuglog,"got message via TCP...");fflush(debuglog);
#endif
			    if (typemode[7]) {
				msgouthandle=fopen(fname[7],"a");
				if (!msgouthandle) return -emsg(45);
				/* should we add a newline? */
				retval=fwrite(recbf,sizeof(char),
					      rhead.length,msgouthandle);
#ifdef DEBUG
				fprintf(debuglog,"retval from fwrite is :%d...",
					retval);fflush(debuglog);
#endif
				if (retval!=(int)rhead.length) return -emsg(46);
				fflush(msgouthandle);
				fclose(msgouthandle);
#ifdef DEBUG
				fprintf(debuglog,"message>>%40s<< sent to msgouthandle.\n",recbf);
				for (ii=0;ii<(int)rhead.length;ii++) {
				    fprintf(debuglog," %02x",recbf[ii]);
				    if ((ii & 0xf)==0xf) fprintf(debuglog,"\n");
				}
				fprintf(debuglog,"\n");fflush(debuglog);
#endif
				break;
			    } else {return -emsg(47); /* do not expect msg */
			    }
			case 2: /* got errc packet */
			    if (typemode[9]) {
				write(ercouthandle,recbf,rhead.length);
			    }
			    break;
			default:
			    return -emsg(48); /* unexpected data type */
		    }
		    receivemode=0; /* ready to read next */
		    receiveindex=0;
		}
	    }
	    if (FD_ISSET(ercinhandle,&readqueue)){
		switch (packinmode) {
		    case 0: /* wait for header */
			packinmode=1; erci_idx=0;
		    case 1: /* finish reading header */
			retval=read(ercinhandle,&ercbf[erci_idx],
				    sizeof(struct errc_header)-erci_idx);
			if (retval==-1) {
			    if (errno==EAGAIN) break;
			    fprintf(stderr,"errno: %d ",errno);
			    return -emsg(72);
			}
			erci_idx+=retval;
			if (erci_idx<sizeof(struct errc_header)) break;
			/* got header, read data */
			if (ehead->length > LOC_BUFSIZE2) return -emsg(73);
			packinmode=3; /* erci_idx continues on same buffer */
		    case 3: /* read more data */
			retval=read(ercinhandle,&ercbf[erci_idx],
				    MIN(LOC_BUFSIZE2,ehead->length)-erci_idx);
			if (retval==-1) {
			    if (errno==EAGAIN) break;
			    fprintf(stderr,"errno: %d ",errno);
			    return -emsg(74);}
			erci_idx+=retval;
			if (erci_idx >=ehead->length)
			    packinmode = 4; /* done */
			break;
		}
	    }
	    if (FD_ISSET(fileno(cmdhandle),&readqueue)) { 
		cmdmode=0; /* in case something goes wrong */
		/* a command is coming */
#ifdef DEBUG
		fprintf(debuglog,"got incoming command note\n");fflush(debuglog);
#endif
		if (1!=fscanf(cmdhandle,FNAMFORMAT,transfername)) 
		    return -emsg(62);
		
		if (sscanf(transfername,"%x",&srcepoch)!=1) {
		    if (verbosity>2) printf("file read error.\n");
		    if (ignorefileerror) { goto parseescape;
		    } else { return -emsg(52);}
		}
#ifdef DEBUG
		fprintf(debuglog,"command read in:>>%s,,\n",transfername);fflush(debuglog);
#endif
		/* consistency check for messages? */
		if (srcepoch<oldsrcepoch) {
		    fprintf(cmdinhandle,"*cmdin: %s\n",transfername);
		    fflush(cmdinhandle);
		    goto parseescape;
		}
		oldsrcepoch=srcepoch;
		fprintf(cmdinhandle,"cmdin: %s\n",transfername);
		fflush(cmdinhandle);
		strncpy(ftnam,fname[0],FNAMELENGTH-1);
		ftnam[FNAMELENGTH-1]=0;
		strncat(ftnam,transfername,FNAMELENGTH);
		ftnam[FNAMELENGTH-1]=0;
#ifdef DEBUG
		fprintf(debuglog,"transfername: >>%s<<\n",ftnam);fflush(debuglog);
#endif
		if (stat(ftnam,&srcfilestat)) { /* stat failed */
		    /* if (verbosity>2) */
#ifdef DEBUG
		    fprintf(debuglog,"(1)file read error.\n");fflush(debuglog);
#endif
		    if (ignorefileerror) { goto parseescape;
		    } else { return -emsg(50);}
		}
		if (!S_ISREG(srcfilestat.st_mode)) {
		    /* if (verbosity>2) */
#ifdef DEBUG
		    fprintf(debuglog,"(2)file read error.\n");fflush(debuglog);
#endif
		    if (ignorefileerror) { goto parseescape;
		    } else { return -emsg(51);}
		}
		if (srcfilestat.st_size > LOC_BUFSIZE) return -emsg(60);
		cmdmode=1;
	    }
	parseescape:
	    if (typemode[6]) /* there could be a message */
		if (FD_ISSET(msginhandle,&readqueue)) {
		    /* read message */
		    retval=read(msginhandle,message,MESSAGELENGTH);
#ifdef DEBUG
		    fprintf(debuglog,"got local message in event; retval frm read:%d\n",retval);fflush(debuglog);
#endif
		    if (retval==-1) return -emsg(57);
		    if (retval>=MESSAGELENGTH) return -emsg(58);
		    message[MESSAGELENGTH-1]=0; /* security termination */
		    message[retval]=0;
		    /* debug logging */
#ifdef DEBUG
		    fprintf(debuglog,"message sent:>>%s<<",message);fflush(debuglog);
		    fflush(debuglog);
#endif
		    messagemode=1;
		}
	    if (FD_ISSET(commskt,&writequeue)) { /* check writing */
#ifdef DEBUG
		fprintf(debuglog,"writeevent received, writemode:%d\n",writemode);fflush(debuglog);
#endif
		switch (writemode) {
		    case 0: /* nothing interesting */
                        /* THIS SHOULD NOT HAPPEN */
#ifdef DEBUG
			fprintf(debuglog,"nothing to write...\n");fflush(debuglog);
#endif
			break;
		    case 1: /*  write header */
			retval=write(commskt,&((char *)&shead)[writeindex],
				     sizeof(shead)-writeindex);
#ifdef DEBUG
			fprintf(debuglog,"sent header, want:%d, sent:%d\n",
				sizeof(shead)-writeindex, retval);fflush(debuglog);
#endif
			if (retval==-1) return -emsg(55);
			writeindex+=retval;
			if (writeindex<(int)sizeof(shead)) break;
			writeindex=0;writemode=2; /* next level... */
			/* printf("written header\n"); */
		    case 2: /* write data */
			retval=write(commskt,&sendbf[writeindex],
				     shead.length-writeindex);
#ifdef DEBUG
			fprintf(debuglog,"send data;len: %d, retval: %d, idx %d\n", 
			   shead.length,retval,writeindex);fflush(debuglog);
#endif
			if (retval==-1) return -emsg(56);
			writeindex+=retval;
			if (writeindex<(int)shead.length) break;
			writemode=3;
			/* if (verbosity>1) */
#ifdef DEBUG
			fprintf(debuglog,"sent file\n");fflush(debuglog);
#endif
		    case 3: /* done... */
			switch (shead.type) {
			    case 0: cmdmode=0; /* file has been sent */
				/* remove source file */
				if (killmode) {
				    if (unlink(ftnam)) return -emsg(63);
				}
				sendbf=NULL; /* nothing to be sent from this */
				break;
			    case 1: messagemode=0;sendbf=NULL;
				break;
			    case 2: packinmode=0;sendbf=NULL;
				break;
			}
			writemode=0; break;
		}
	    }

	    /* test for next transmission in the queue */
	    if (messagemode && !writemode) { /* prepare for writing */
		/* prepare header */
#ifdef DEBUG
		fprintf(debuglog,"prepare for sending message\n");fflush(debuglog);
#endif
		shead.type=1; shead.length=strlen(message)+1; shead.epoch=0;
		/* prepare for sending message buffer */
		writemode=1;writeindex=0; sendbf=message;
		continue; /* skip other tests for writing */
	    } 
	    if (cmdmode && !writemode) {
		/* read source file */
		srcfile=open(ftnam,READFILEMODE);
		if (srcfile==-1) {
		    fprintf(debuglog,"return val open: %x, errno: %d\n",
			    srcfile,errno);
		    fprintf(debuglog,"file name: >%s<\n",
			    ftnam);
		    return -emsg(53);
		}
		retval=read(srcfile,filebf,LOC_BUFSIZE);
		close(srcfile);
#ifdef DEBUG
		fprintf(debuglog,"prepare for sending file; read file with return value %d\n",retval);fflush(debuglog);
#endif
		if (retval!=srcfilestat.st_size) return -emsg(54);
		/* prepare send header */
		shead.type=0; shead.length=retval; shead.epoch=srcepoch;
		writemode=1; writeindex=0; /* indicate header writing */
		sendbf=filebf;
		continue; /* skip other test for writing */
	    }
	    if ((packinmode==4) && !writemode) { /* copy errc packet */
		/* prepare header & writing */
		shead.type=2; shead.length=ehead->length; shead.epoch=0;
		writemode=1;writeindex=0;sendbf=ercbf;
	    }
	    
	}
#ifdef DEBUG
	fprintf(debuglog,"loop\n");fflush(debuglog);
#endif
	continue; /* loop is fine */
    reconnect: 
	/* close open sockets and wait for next connection */
	close(commskt);
#ifdef DEBUG
	fprintf(debuglog,"comm socket was closed.\n");fflush(debuglog);
#endif
	if (commskt==sendskt) { /* renew send socket */
	    sendskt=socket(AF_INET,SOCK_STREAM,0); /* outgoing packets */
	    if (!sendskt) return -emsg(16);
	    /* client socket for sending data */
	    sendsktlen=strlen(fname[2]);
	    sendadr.sin_family = AF_INET;
	    remoteinfo=gethostbyname(fname[2]);
	    if (!remoteinfo) {
		switch(h_errno) {
		    case HOST_NOT_FOUND: return -emsg(21);
		    case NO_ADDRESS: return -emsg(22);
		    case TRY_AGAIN: return -emsg(23);
		    default: return -emsg(24);
		}}
	    /* extract host-IP */
	    sendadr.sin_addr=*(struct in_addr *)*remoteinfo->h_addr_list;
	    sendadr.sin_port=htons(portnumber);
	}
	if (verbosity>0) { 
	    printf("disconnected.\n");
	    fflush(stdout);
	}
	commskt=0;
    } while (noshutdown); /* while link should be maintained */
    
    /* end benignly */
    printf("ending benignly\n");

    /* clean up sockets */
    fclose(cmdhandle);
    /* close(cmdhandle); */
    /* close(keepawake_handle); */
    if (typemode[6]) { close(msginhandle); close(keepawake_h2); }
    close(recskt); close(sendskt);
    if (typemode[8]) { close(ercinhandle); close(keepawake_h3); }
    if (typemode[9])  close(ercouthandle);
    /* free buffer */
    free(recbf); free(filebf); free(ercbf);
    fclose(cmdinhandle);

    fclose(debuglog);
    return 0;
}
