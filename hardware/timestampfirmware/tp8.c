/*  tp8.c: This is the firmware for the cypress FX2 USB adapter in the
           timestamp unit, providing a fast interface to process detection
	   events. This version (tp8) is a cleaned up code from earlier
	   internal versions. 
	   
 Copyright (C) 2006-2010 Christian Kurtsiefer, National University
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

Rationale:     To provide a USB interface for the 64 bit wide event FIFO
               with a large bandwidth, and some low bandwidth commands to
	       adjust various control parameters of the timestamp unit.

Interface:     The firmware provides, apart from the standard USB handshake
               elements via endpoint 0 a command interface via EP1OUT, and
	       a readback interface, mainly for diagnostic information, via
	       the EP1IN endpoint. The bulk of the timestamp event info is
	       communicated to the host via endpoint EP2IN via bulk transfers.

Performance:   Can process about 2.2 Mevents/sec in USB2 mode, then starts
               limiting the events raining into the card once the external
	       FIFO reaches a certain watermark.

Useful sources of information: 
               FX2 Technical reference manual
               CY7C43683/663/643 external FIFO data sheet (chip obsoleted..)
	       NBC12430 RF generator data sheet (Onsemi)
	       AD5318 Digital-to-Analog converter data sheet (Analog Devices)
	       SDCC compiler manual

Issues:        The USB descriptor tables need to start on n even address.
               look for the output in the .rst files if this is the case,
	       otherwise add a dummy variable in xuxu..

ToDo:          use flowstates in GPIF engine to get more efficient transfer
               Fix Syncdelay to something sensible
               allow for higher processor speeds
               parameter readback for phasetable. needs definition of format

*/

#include "fx2regs_c.h"
#include "fifobithelpers.h"

#define firmware /* this selects the one-byte version of the EP 1 commands */
#include "usbtimetagio.h"

/* static variables */
static __bit bitSUDAVSeen = 0; /* EP0 irq */
static __bit bitURESSeen = 0;  /*  bus reset */
static __bit bitEP1Seen = 0;   /* EP 1 activty */
static __bit bitEP1INseen =0; /* for test */
static __bit bitTimerSeen = 0;
static __bit bitGPIFrunning = 0; /* 1 if GPIF is working with internal fifo */
static __bit bitDoFlush = 0; /* to indicate a necessary flush */
static __bit bitOverflowCondition = 0; /* no overflow cond */
static __bit bitDesiredInhibitStatus = 0; /* to keep track of changes in ovfl */
__xdata char altsetting = 0; /* 0: naked, 1: all ep interface settings */
__xdata char configuration = 1; /* 1: full sp, 2: high sp */

__xdata char bpstorage;
__xdata char dpstorage; /* to keep state of latched
			 contents of ports B and D */
__xdata char ifconfig_ports; /* keeps port pattern */
__xdata char ifconfig_gpif; /* keeps GPIF pattern */
__xdata char ifconfig_active; /* No ports there, maybe gpif or bus pattern */

__xdata char autoflushvalue; /* when to flush */
__xdata char flushcount; /* counts down timer clicks */
__xdata char hitcnt; /* how often was there the same empty+bcnt condition */
__xdata unsigned int oldcnt,newcnt; /* to buffer byte counts */
__xdata unsigned int RFchoice;   /* data sent to pll or HW equivalent */


/* FIFO serial load stuff */
__xdata unsigned int FIFOupperwatermark;

/* static gobal variables for commands  */
__xdata char ep1command; /* parameter for status request */

/* generic delay */
static void SpinDelay(unsigned int count) {
    unsigned int c=count;
    while (c > 0) c -= 1;
}

#define SYNCDELAY SpinDelay(3); /* This is generous, probably needs less */

/* setup ports in a safe state initially and carry out master reset of FIFO;
   leave the timestamp card in a idling but reasonable state */
static __code void initPorts() {
    OEA = 0xe0;  /* three msb are output */
    /* transparent latch, disable sample, off extfifo */
    IOA = bmSampleInhibit | bmfifo_nCSB | bmNLatchEnable;
    bitDesiredInhibitStatus = 1;

    OED = 0xff; /* config port D completely as output;  */
    /* zero port to get FIFO into a reset state; furthermore:
       BE=0 (little endian), FS0=0, FS1=1 (serial prog) */
    IOD = bmFIFO_FS1; /* if PD7 is connected to FS1 */
    /* in case FS1 is connected to ctl1 */
    GPIFCTLCFG = 0;     /* CMOS, non-tristatable */
    GPIFIDLECTL = 0x02; /* idle state for CTL0=ENB=0, CTL1=FS1=1 */
    
    OEB = 0xff; /* port B is all output as well */
    bpstorage = bmDac_nSYNC | bmRfsrc_xtalsel;
    IOB = bpstorage; /* internal xtal, dacsync off, rfs_pload in
			prepare state */
    SpinDelay(10); /* for Clock generator to realize reset */
    bpstorage |= bmRfsrc_nPLOAD; /* load hardwired clock signals into PLL */
    IOB = bpstorage;

    /* carry out FIFO master reset; let MRS=0 sink in for a while.. */
    SpinDelay(40);
    /* latch setup info into FIFO with some hold time */
    IOD = bmFIFO_FS1 | bmFIFO_nMRS1 | bmFIFO_nMRS2 | bmFIFO_nWRB ; 

    /* FS1=1, FS0=0, take device out of reset and choose CY standard mode,
       configure port B for read (!!avod conflict by having CSB high before! */
    IOD = bmFIFO_FS1 | bmFIFO_nPRS | bmFIFO_nMRS1 | bmFIFO_nMRS2 
	| bmFIFO_nWRB | bmFIFO_BEnFWFT;   
    dpstorage = IOD;  /* keep for later */

    /* freeze data bits for later usage: switch latch to hold (sbit to 0) */
    IOA5 = 0 ; 

    RFchoice=0x790; /* due to reset */
}

/* start FIFO data acquisition */
static void StartFIFOAcquisition() {
    GPIFTCB0=1; /* This sucker took forever to get into the code... 
		   need to have at lesat one transaction scheduled or the
		   box hangs. */
    SYNCDELAY;
    EP2FIFOCFG = bmWORDWIDE | bmAUTOIN;
    SYNCDELAY;
    /* disable the stop bit */
    GPIFREADYCFG = 0; /* set unit in running mode */
    SYNCDELAY;
    /* actually start the transfer */
    GPIFTRIG= bmGPIF_READ | bmGPIF_EP2_START;
    SYNCDELAY;
}
/* stop FIFO data acquisition with correct byte numner */
static void StopFIFOAcquisition() {
    /* issue a halt bit... */
    GPIFREADYCFG = bmINTRDY; 
    /* ...and wait until we are done */
    while (!(GPIFTRIG & bmGPIF_IDLE));
}


/* prepare reading waveform. This is the main transfer waveform from the
   ext fifo to the internal fifo. Currently, this works not with a flowstate.

*/
/* seems to work with 7 cycles per word */
static __code char InitWaveData0[] = {
    /* start with waveform 0 (FIFO READ) */
    0x0e, 0x01, 0x01, 0x01, 0x01, 0x01, 0x38, /* length/branch info 0-7 */
    0x00, /* reserved */
    0x01, 0x00, 0x02, 0x02, 0x02, 0x02, 0x01, /* opcode info 0-7 */
    0x00, /* reserved */
    0x02, 0x03, 0x03, 0x03, 0x03, 0x02, 0x02, /* output info 0-7 */
    0x00, /* reserved */
    0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, /* logic info 0-7 */
    0x00, /* reserved */
};

/* waveform to write data serially into the watermark outputs. This command
   will write a single bit, synchronized with the external clock. It assumes
   a 30 MHz operation internally, and a 1.9MHz operation of the fifo clka.
   step 0: send data to fd
   step 1: goto idle if break signal (intrdy) without ctl1 to 0
   step 2: wait for rdy1 to go to 1, keep ctl1 to 1, ctl0 to 0.
   step 3: wait for rdy1 to go to 0, keep ctl1 to 1, ctl0 to 0.
   step 4: a few (2) adjust cycles to find the right corner (ctl1=1, ctl0=0)
   step 5: eight cycles w ctl1=0
   step 6: pre-ilde with ctl1=1
*/
static __code char InitWaveData3[] = {
    /* waveform 3 (Single  WRITE) */
    0x04, 0x3a, 0x1a, 0x1c, 0x02, 0x08, 0x03, /* length/branch info 0-7 */
    0x00, /* reserved */
    0x02, 0x03, 0x03, 0x03, 0x02, 0x02, 0x02, /* opcode info 0-7 */
    0x00, /* reserved */
    0x02, 0x02, 0x02, 0x02, 0x02, 0x00, 0x02, /* output info 0-7 */
    0x02, /* reserved */
    0x00, 0x7f, 0x49, 0x49, 0x00, 0x00, 0x00, /* logic info 0-7 */
    0x00, /* reserved */
};


static void LoadWaveformGPIF() {
    char i;
    /* set EP2GPIFFLGSEL see p. 15-97 of FX2 TRM*/
    EP2GPIFFLGSEL = 0x02; /* choose full flag as programmable flag */

    GPIFABORT = 0xff; /* stop all WFS */
    /* load wf data; 0: FIFO READ, 1: FIFO WR (to load AFREG?) */
    for (i=0;i<32;i++) {/* to load waveform data */
	WAVEDATA[i]=InitWaveData0[i]; SYNCDELAY;
	WAVEDATA[i+96]=InitWaveData3[i]; SYNCDELAY;
    }
}
/* To bring FIFO2 in clean state */
static void fifo2reset() {
    FIFORESET = bmNAKALL; 
    SYNCDELAY;
    FIFORESET = 0x02; /* reset FIFO in EP2 */
    SYNCDELAY;
    FIFORESET = 0; /* normal op */
    
}

/* init CPU stuff */
static void initCPU() {
    CPUCS = bmCLKSPD12MHZ | bmCLKOE; /* output CPU clock */
    REVCTL = bmENH_PKT | bmDYN_OUT; /* don't know if this helps */

    WAKEUPCS = bmWU | bmWU2;     /* disable wakeup machinery */
    IE = 0;   /* disable most irq */
    EIE = 0;  /* disable external irq */
    EXIF = 0; /* clear some IRQs */
    EICON = 0; /* disable resume irqs and others */
    IP = 0;    /* no high prio for most irq */

    /* interface configuration */
    /* internal 30 MHz clock, IFCLOCK on, neg polarity, sync operation, 
       ports B/D act as ports bm3048MHZ initially */
    ifconfig_ports = bmIFCLKOE | bmIFCLKSRC  | bmIFCLKPOL
	; /* switch to ports */
    ifconfig_gpif =  bmIFCLKOE | bmIFCLKSRC  | bmIFCLKPOL 
	| bmIFGPIF  ; /* for later */
    ifconfig_active = ifconfig_ports; /* initially */
    IFCONFIG = ifconfig_ports;

}
/* at a few occasions we go for a....*/
void resetTogglebits(){
    TOGCTL = 0; TOGCTL = bmRESETTOGGLE; TOGCTL = 0; /* OUT 0 */
    /* IN 0 */
    TOGCTL = 0 | bmTOGCTL_IO; TOGCTL = 0 | bmTOGCTL_IO | bmRESETTOGGLE;
    TOGCTL = 0 | bmTOGCTL_IO;
    /* Out 1 :*/
    TOGCTL = 1; TOGCTL = 1 | bmRESETTOGGLE; TOGCTL = 1;
    /* IN 1 : */
    TOGCTL = 1 | bmTOGCTL_IO; TOGCTL = 1 | bmTOGCTL_IO | bmRESETTOGGLE; 
    TOGCTL = 1 | bmTOGCTL_IO;
    /* IN 2 : */
    TOGCTL = 2 | bmTOGCTL_IO; TOGCTL = 2 | bmTOGCTL_IO | bmRESETTOGGLE; 
    TOGCTL = 2 | bmTOGCTL_IO;

}

/* switch on corresponding IRQ's and set data toggle bits for relevant EPs 
   for a given configuration and alternate setting */
static void initEndpoints() {
    switch (altsetting) {
	case 0: 
	    EP1OUTCFG = bmTYPE1; /* disabled */
	    EP2CFG = bmDIR | bmBULK | bmQUADBUF; 
	    EP1INCFG = bmTYPE1;
	    EPIE = 0; /* no Endpoint IRQ */
	    /* shut off all nonsense */
	    GPIFABORT=0xff;
	    break;
	case 1: 
	    EP1OUTCFG = bmVALID | bmTYPE1; /* bulk transfer */
	    EP2CFG = bmDIR | bmBULK | bmQUADBUF | bmVALID; 
	    EP1INCFG = bmVALID | bmTYPE1;
	    EPIE = bmEPIE_EP1OUT; /* enable subset int 2 */
	    
	    break;
    }
    /* reset data toggle bit EP 0 and 1 OUT direction */
    resetTogglebits();

    /* arm OUT endpoints */
    SUDPTRCTL = 0; /* manual */
    EP0BCH = 0; EP0BCL = 0x40; /* arm EP0 */
    if (altsetting) {
	EP1OUTBC = 0x40; /* arm EP1in */
    }
    /* set EP2 autoinlen to match the current speed: 64 bytes hi, 512 full */
    if (USBCS & bmHSM) {
	EP2AUTOINLENH = 512>>8; EP2AUTOINLENL = 512 & 0xff;
	EP2FIFOBCH    = 512>>8; EP2FIFOBCL    = 512 & 0xff;
    } else {
	EP2AUTOINLENH =  64>>8; EP2AUTOINLENL =  64 & 0xff;
	EP2FIFOBCH    =  64>>8; EP2FIFOBCL    =  64 & 0xff;
    }   
}


/* set whatever needs to be set for the USB engine before re-enumeration */
static void initUSB() {
    /* allow only full speed operation */
    /* enable EP0 if needed, EP1OUT, rest is dead */
    EP1INCFG  = bmTYPE1; /* disable */
    /* initialize USB package thing */

    /* configure EP2 as input EP, bulk, 512 bytes, quad buffered; not valid */
    EP2CFG = bmDIR | bmBULK | bmQUADBUF; 
    SYNCDELAY;
    EP2FIFOCFG = bmAUTOIN | bmWORDWIDE;

   /* configure EP1OUT for bulk transfer */
    initEndpoints();

    USBIRQ = 0xff; /* clear pending USB irqs */
    USBIE = bmURES | bmSUDAV;
    EUSB = 1;  /* enable USB irqs */
    
}

/***********************************************************************/
/* USB utility stuff */

static void ReEnumberate() {
    USBCS &= ~bmNOSYNSOF;  /* allow synthesis of missing SOF */
    USBCS |=  bmDISCON;    /* disconnect */
    USBCS |=  bmRENUM;     /* RENUM = 1; use own device model */
    SpinDelay(0xf401);     /* wait a while for the host to detect */
    USBCS &= ~bmDISCON;    /* reconnect */
    USBCS |=  bmNOSYNSOF;  /* disallow synthesis of missing SOF */
}


/***********************************************************************/
/* usb IRQ stuff */
static void isrUsb(void) __interrupt (8) __using (3)  {/* critical */
    EXIF &= ~bmEXIF_USBINT; /* clear USBINT interrupt */
    if (  USBIRQ & bmSUDAV ) { /* Setup Data available */
	USBIRQ = bmSUDAV; bitSUDAVSeen = 1;
    }
    if (  USBIRQ & bmURES ) { /* USB bus reset */
	USBIRQ = bmURES; bitURESSeen = 1;
    }
    /* EP IRQ's */
    if (EPIRQ & bmEPIE_EP1OUT) {
	EPIRQ = bmEPIE_EP1OUT; bitEP1Seen =1; /* marker for later */
    }

}

/***********************************************************************/
/* EP0 service routines */
/* The xuxu fillers may be needed to keep Descriptor tables word-aligned */
static __code char xuxu[]={0};
static __code char Descriptors[] = { /* only a full speed device */
    0x12, 0x01, 0x00, 0x02, 0xff, 0xff, 0xff, 0x40, // device, usb2.0,..
    0xb4, 0x04, 0x34, 0x12, 0x01, 0x02,  // cypress, dev 1234, rel 2.1
    0x00, 0x00, 0x00, 0x01, // no indx strings, 1 configuration

    0x0a, 0x06, 0x00, 0x02, 0xff, 0xff, 0xff, // device qualifier
    0x40, 0x01, 0x00,  //64 bytes pkts, 1 config

    0x09, 0x02, 0x30, 0x00, 0x01, // defaut config descriptor (len: 41 bytes)
    0x01, 0x00, 0xc0, 0x00,  // config #1, no buspower, 0mA

    0x09, 0x04, 0x00, 0x00, 0x00, // interface0, alt setting 0, #EP over 0
    0xff, 0xff, 0xff, 0x00, // no strings

    0x09, 0x04, 0x00, 0x01, 0x03, // if0, alt set 1, two more ( EP1out/EP2 )
    0xff, 0xff, 0xff, 0x00, 
    
    0x07, 0x05, 0x01, 0x02, 0x40, 0x00, 0x00, // EP1out, bulk, 64 byte, no poll
    0x07, 0x05, 0x81, 0x02, 0x40, 0x00, 0x00, // EP1in, bulk, 64 byte, no poll
    0x07, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00, // EP2in, bulk, 64 byte, no poll

    0x00,  // termination of descriptor list
};

/* some filler to keep stuff word-aligned */
static __code char xuxu2[]= {0};  

static __code char Descriptors2[] = { /* table for high speed operation */

    0x12, 0x01, 0x00, 0x02, 0xff, 0xff, 0xff, 0x40, // device, usb2.0,..
    0xb4, 0x04, 0x34, 0x12, 0x01, 0x02,  // cypress, dev 1234, rel 2.1
    0x01, 0x02, 0x03, 0x01, // some strings, 1 configuration

    0x0a, 0x06, 0x00, 0x02, 0xff, 0xff, 0xff, // device qualifier
    0x40, 0x01, 0x00,  //64 bytes pkts, 1 config

    0x09, 0x02, 0x30, 0x00, 0x01, // defaut config descriptor (len: 34 bytes)
    0x01, 0x00, 0xc0, 0x00,  // config #1, no buspower, 0mA

    0x09, 0x04, 0x00, 0x00, 0x00, // interface0, alt setting 0, #EP over 0
    0xff, 0xff, 0xff, 0x00, // no strings

    0x09, 0x04, 0x00, 0x01, 0x03, // if0, alt set 1, two more ( EP1out, ep2in )
    0xff, 0xff, 0xff, 0x00, 
    
    0x07, 0x05, 0x01, 0x02, 0x00, 0x02, 0x00, // EP1out, bulk, 64 byte, no poll
    0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00, // EP1in, bulk, 512 byte, no poll
    0x07, 0x05, 0x82, 0x02, 0x00, 0x02, 0x00, // EP2in, bulk, 512 byte, no poll

    0x00, // termination of descriptor list
};


/* some filler to keep stuff word-aligned */
static __code char xuxu3[]= {0};  
static __code char StringDescriptors[] = { /* table for strings */
    0x04, 0x03, 'l',0,  // dummy but read??
    0x40, 0x03, 'C',0, 'e',0, 'n',0, 't',0, 'r',0, 'e',0, ' ',0,
                'f',0, 'o',0, 'r',0, ' ',0, 'Q',0, 'u',0, 'a',0,
                'n',0, 't',0, 'u',0, 'm',0, ' ',0, 'T',0, 'e',0,
                'c',0, 'h',0, 'n',0, 'o',0, 'l',0, 'o',0, 'g',0,
                'i',0, 'e',0, 's',0, // Manufacturer

    0x4c, 0x03, 'T',0, 'i',0, 'm',0, 'e',0, 's',0, 't',0, 'a',0, 'm',0, 'p',0,
                ' ',0, 'C',0, 'a',0, 'r',0, 'd',0, ' ',0, 'R',0, 'e',0, 'v',0, 
                ' ',0, '2',0, ' ',0, '/',0, ' ',0, '4',0, 'k',0, ' ',0, 'F',0,
                'I',0, 'F',0, 'O',0, ' ',0, '(',0, '3',0, '.',0, '3',0, 'V',0,
                ')',0, 
    0x06, 0x03, 'x',0, 'x',0, //Serial number

    0x00 // termination of descriptor list

};

static void ctrlGetStatus() {
    unsigned char a;
    SUDPTRCTL=1; /* simple send...just don't use SUDPTRL */
    EP0BCH = 0x00; EP0BUF[1] = 0x00; /* same for all requests */
    switch (SETUPDAT[0]) { /* bmRequest */
	case 0x80: // IN, Device (Remote Wakeup and Self Powered Bit)
	    EP0BUF[0] = 0x01; /* no Remote Wakeup, Self-powerd Device */
	    EP0BCL    = 0x02; /* 2 bytes, triggers transfer */
	    break;

	case 0x81: // IN, Get Status/Interface
	    EP0BUF[0] = 0x00;
	    EP0BCL    = 0x02; /* 2 bytes */
	    break;

	case 0x82: // IN, Endpoint (Stall Bits)
	    switch (SETUPDAT[4] & 0xf) { /* extract number */
		case 0: a=EP0CS; break;
		case 1: a=(SETUPDAT[4]&0x80)?EP1INCS:EP1OUTCS; break;
		case 2: a=EP2CS; break;
		case 4: a=EP4CS; break;
		case 6: a=EP6CS; break;
		case 8: a=EP8CS; break;
		default: a=1; break; /* or better Stall? */
	    }
	    EP0BUF[0] = a & 1; /* return stall bit or 1 in case of err */
	    EP0BCL    = 0x02; /* 2 bytes */
	    break;
	default:  /* STALL indicating Request Error */
	    EP0CS = bmEPSTALL; 
	    break;
    }
}

/* vombines clear or set feature; v=0: reset, v=1: set feature */
static void ctrlClearOrSetFeature(char v) {
    char a; /* to hold endpoint */
    switch (SETUPDAT[0]) { /* bmRequest */
	case 0x00: // Device Feature (Remote Wakeup)
	    if (SETUPDAT[2] != 0x01) { /* wValueL */
		EP0CS = bmEPSTALL;
	    }
	    break;
	case 0x02: // Endpoint Feature (Stall Endpoint)
	    if (SETUPDAT[2] == 0x00) { /* clear stall bit */
		a=SETUPDAT[4] & 0xf;
		switch (a) {
		    case 0: EP0CS=v; break;
		    case 1: 
			if (SETUPDAT[4] & 0x80) {
			    EP1INCS=v; 
			} else { 
			    EP1OUTCS =v;
			}
			break;
		    case 2: EP2CS=v; break;
		    case 4: EP4CS=v; break;
		    case 6: EP6CS=v; break;
		    case 8: EP8CS=v; break;
		}
		/* in case of set feature clear toggle bit */
		if (v) { 
		    if (SETUPDAT[4] & 0x80) a |=bmTOGCTL_IO; /* set dir */
		    /* back to data stage 0 */
		    TOGCTL = a; TOGCTL = a | bmRESETTOGGLE; TOGCTL = a;
		}
		break;
	    } /* else follow stall... */ 
	default: 
	    EP0CS = bmEPSTALL; break;
    }
}
static void ctrlGetDescriptor() {
    char key   = SETUPDAT[3]; /* wValueH */
    char index = SETUPDAT[2]; /* wValueL */
    char count = 0;
    char seen = 0; /* have seen a string */
    static __code char *current_DP;
    current_DP = (USBCS & bmHSM)? Descriptors2:Descriptors; 
    /* try to make other speed config */
    if (key==7) {
      current_DP = (USBCS & bmHSM)? Descriptors:Descriptors2;
      key=2; /* go into 'retrieve configuration' state */
    }
    if (key==3) { /* get string table */
      current_DP = StringDescriptors;
    }
    SUDPTRCTL = bmSDPAUTO; /* allow for automatic device reply */
    for (; current_DP[0]; current_DP += current_DP[0])
      if ((current_DP[1] == key) && (count++ == index)) {
	SUDPTRH = (char)(((unsigned int)current_DP)>>8)&0xff;
	SUDPTRL = (char)( (unsigned int)current_DP    )&0xff;
	seen=1;
	break;
      }
    
    if (!seen) EP0CS = bmEPSTALL; /* did not find descriptor */
}


static void ctrlGetConfiguration() {
  SUDPTRCTL=1; /* simple send */
  EP0BUF[0] = configuration;
  EP0BCH    = 0x00; EP0BCL    = 0x01; /* 1 byte, trigger transfer */
}

static void ctrlSetConfiguration() {
    if (SETUPDAT[2] & 0xfe) { /* not config 0 or 1 */
	EP0CS = bmEPSTALL;
    } else {
	configuration = SETUPDAT[2];
	resetTogglebits;
    }
}

static void ctrlGetInterface() {
  SUDPTRCTL=1; /* simple send */
  EP0BUF[0] = altsetting;
  EP0BCH = 0x00; EP0BCL = 0x01; /* 1 byte */
}

static void ctrlSetInterface() {
    if (SETUPDAT[2] & 0xfe) { /* not config 0 or 1 */
	EP0CS = bmEPSTALL;
    } else {
	altsetting = SETUPDAT[2];
	initEndpoints(); /* switch on/off end points */
    }
}

/* EP0 setup commands */
static void doSETUP() {
    switch  (SETUPDAT[1]) { /* bRequest */
	case 0x00: ctrlGetStatus();         break;
	case 0x01: ctrlClearOrSetFeature(0);      break; /* clear */
	    /*case 0x02: EP0CS = bmEPSTALL;       break; */
	case 0x03: ctrlClearOrSetFeature(1);        break; /* set */
	    /* case 0x04: EP0CS = bmEPSTALL;       break;  reserved */
	/* case 0x05:  SetAddress */
	case 0x06: ctrlGetDescriptor();     break;
	    /*  case 0x07:   SetDescriptor     break; */
	case 0x08: ctrlGetConfiguration();  break;
	case 0x09: ctrlSetConfiguration();  break;
	case 0x0a: ctrlGetInterface();      break;
	case 0x0b: ctrlSetInterface();      break;
	/* case 0x0c:  Sync: SOF           break; */
	default: EP0CS = bmEPSTALL ;         break;
    }
    EP0CS = bmHSNAK; /* close hs phase */
    bitSUDAVSeen = 0;
}
/***************************************************************************/
/*
 working procedures to communicate with the timestamp card. Some adjustment
 data lines are shared with the event bus, which requires some switching

*/
/* Stop GPIF and allow line access */
static __code void HaltGPIFforLineaccess() {
    /* Signal GPIF to stop if running */
    if (bitGPIFrunning) StopFIFOAcquisition();
    /* disable /CSB */
    IOA6 = 1; /* /CSB line via sbit */
    IOB = bpstorage; IOD = dpstorage; /* restore settings */
    /* switch to IOLINES */
    IFCONFIG = ifconfig_ports;
    IOA5 = 1; /* transparent latch */
}
static __code void ResumeGPIFafterLineaccess() {
    IOA5 = 0; /* Latch status */
    /* TODO: ports to FD again */
    IFCONFIG = ifconfig_active;
    IOA6 = 0; /* CSB line */
    /* Resume GPIF if running */
    if (bitGPIFrunning) StartFIFOAcquisition(); /* evenally resume */
}

/* serial data sending code for DACs and RFsource. The content is loaded
   into the global ShiftTarget variable, and then specific submit functions
   are called. The IOB and IOD registers have to be routed to the data lines
   before by making the latch transparent. */
__data unsigned int ShiftTarget; /* store & process serial data */
/* send serial data to DAC; registers are avaliable already. This code is
   intended to talk to the AD5318 chip from Analog Devices */
static void SubmitDAC() {
    char i; /* serial counter */
    bpstorage |= bmDac_nSYNC | bmRfsrcDac_serclk; /* Sync up, clk=1 */
    IOB = bpstorage; /* this must take 50 nsec min, therefore repeat cmd */
    IOB = bpstorage;
    IOB = bpstorage;
    IOB1 = 0; /* Lower DAC SYNC LINE sync */
    for (i=16;i;i--) { /* loop through all 16 data bits */
	if (ShiftTarget & 0x8000) IOB3=1; else IOB3 = 0; /* set data bit */
	IOB0 = 0; /* lower clock line */
	ShiftTarget <<= 1;
	IOB0 = 1; /* rise clk line again */
    }
    IOB1 = 1; /* rise DAC SYNC line again */
}
static void InitDAC() { /* send a few words to the DAC */
    /* reset DAC data and control registers */
    ShiftTarget = 0xf000; SubmitDAC();
    /* activate all eight channels */
    ShiftTarget = 0xc000; SubmitDAC();
    /* choose refrence/gain to unbuffered reference, gain=1 */
    ShiftTarget = 0x8000; SubmitDAC();
    /* Choose LDAC mode to update on each write (internal LDAC low) */
    ShiftTarget = 0xa000; SubmitDAC();
}
static void InitDAC2() { /* program DAC to some standard values */
     /* set coinicdence time window varactor in channel 0*/
    ShiftTarget = (0<<12) | 10; SubmitDAC();
    /* input threshold to about -0.5V via channel 1 */
    ShiftTarget = (1<<12) | 3586; SubmitDAC();
    /* calibration value for autocalibrate in channel 2 */
    ShiftTarget = (2<<12) | 10; SubmitDAC();
    /* skew value for the fast counter in channel 3; without this,
       the FIFO overflow register cannot be loaded..... */
    ShiftTarget = (3<<12) | 2000; SubmitDAC();   
}
/* send serial data to RFSRC; registers are avaliable already. This code
   talks to the NBC12430 chip from ONsemi. */
static void SubmitRFSRC() {
    char i; /* serial counter */
    bpstorage |= bmRfsrc_nPLOAD; 
    bpstorage &= ~(bmRfsrc_SLOAD | bmRfsrcDac_serclk
		   | bmRfsrcDac_serdata );/* sload=0, clk=0, data=0 */
    IOB = bpstorage;
    for (i=14;i;i--) { /* loop through all 14 data bits */
	if (ShiftTarget & 0x2000) IOB3=1; else IOB3 = 0; /* set data bit */
	IOB0 = 1; /* rise clock line */
	ShiftTarget <<= 1;
	IOB0 = 0; /* lower clk line again */
    }
    IOB2 = 1; /* rise S_LOAD */
    IOB = bpstorage; /* lower bit again and set data to 0 */
}
/* reset timestamp card; goes through a partial reset and keeps the
   inhibit line to 1 */
static void ResetTimestamp() {
    IOA7 = 1; /* set inhibit line */
    bitDesiredInhibitStatus = 1;
    bpstorage &= ~bmSlowcount_nSR; /* slow counter into reset */
    IOB = bpstorage;
    /* initiate partial reset of external FIFO */
    dpstorage &= ~bmFIFO_nPRS; /* lower partial reset */
    IOD = dpstorage;
    SpinDelay(10); /* wait for some time */
    dpstorage |= bmFIFO_nPRS;
    IOD = dpstorage; /* take ext FIFO out of reset */
    bpstorage |= bmSlowcount_nSR;
    IOB = bpstorage; /* take slow counter out of reset */
}


#define upperbitmask 0x2000 /* for a 16 kbyte register 0x2000, here debug */
/* program the AE (almost empty line) of the FIFO serially;
   data is in FIFOupperwatermark */
static void FIFOSerialProgram() {
    unsigned int i;
    char a=dpstorage &= ~0x10;
    char b=dpstorage | 0x10;
    char c=bpstorage; /* low byte */
    char j;
    
    /* prepare FIFO in programmable state */
    IOA6=1; /* safeguards FIFO from nonsense showing up */

    /* lower slowclock frequency */
    IOB = c; IOD = a; /* restore settings */
    IFCONFIG = ifconfig_ports;
    IOA5=1; /* transparentlatch */
    ShiftTarget = 0x590;
    SubmitRFSRC();
    IOA5 = 0; /* Latch status */

    /* prepare GPIF default parameters */
    /* idle state for CTL0=ENB=0, CTL1=FS1=1 is already defined */
    GPIFCTLCFG = 0;     /* CMOS, non-tristatable */
    GPIFIDLECTL = 0x02; /* idle state for CTL0=ENB=0, CTL1=FS1=1 */

    GPIFIDLECS = bmIDLEDRV; /* drive data bus while idle */
    /* switch on GPIF to bus */
    IFCONFIG = ifconfig_gpif;

    GPIFREADYCFG = bmINTRDY; /* choose short path in waveform 
				to set data to FD before unlatching  */
    while (!(GPIFTRIG & 0x80)); /* wait for GPIF to be ready */
    XGPIFSGLDATH = a; XGPIFSGLDATLX = c; /* trigger sending this bit */
    while (!(GPIFTRIG & 0x80)); /* wait for GPIF to be ready */
    GPIFREADYCFG = 0;   /* chose bit sending path this time */

    IOA5 = 1; /* transparent latch */

    /* transfer data */
    for (j=0;j<2;j++) {/* repeat for both registers */
	for (i=upperbitmask;i;i>>=1) {
	    while (!(GPIFTRIG & 0x80)); /* wait for GPIF to be ready */
	    XGPIFSGLDATH = ((i&FIFOupperwatermark)?b:a); /* set/reset bit */
	    XGPIFSGLDATLX = c; /* trigger sending this bit */
	}   
    }
    while (!(GPIFTRIG & 0x80)); /* wait for GPIF to be ready */
    
    /* restore fast clock */
    IOA5 = 0; /* Latch status */
    IOD=dpstorage; /* restore old value */
    IFCONFIG = ifconfig_ports;
    IOA5 = 1; /* transparent latch */
    ShiftTarget = RFchoice;
    SubmitRFSRC();
    IOA5 = 0; /* Latch status */

    /* go into idle state again */
 
    /* restore GPIF parameters for data transfer */
    IFCONFIG = ifconfig_active;
    GPIFIDLECS = 0;  /* tristate GPIF bus */
}


/* setup timer 0 as a 10 msec heartbeat */
static void SetupTimer0() {
    CKCON = 0; /* use clkout/12 for counter 2 */
    RCAP2L = (0xffff-10000) & 0xff;      /* 10 msec */
    RCAP2H = ((0xffff-10000) >> 8 ) &0xff; 
    TR2 = 1; /* 4 normal enable cnt, 16bit autoreload, internal clk  */
}

/* service routine timer0; checks autoflush and eventually forces a pktsend */
static void isrt0(void) __interrupt (5) { /* should this use a bank? */
    TF2 = 0; /* reset timer overflow flag */
    bitTimerSeen = 1; /* make us heared */
}

/* fill EP1 with stats information or indexed data - see ep1command */
static void fillEP1() {
    if (EP1INCS & bmEPBUSY) return; /* wait for next round in polling loop */
    
    switch (ep1command) {
	case 0: /* get status information */
	    EP1INBUF[0]=IOA; /* for the moment, that's all status info */
	    EP1INBC = 1;
	    break;
	case 1: /* get GPIFTRIG register */
	    EP1INBUF[0]=GPIFTRIG;
	    EP1INBC = 1;
	    break;
	case 2: /* get chip revision */
	    EP1INBUF[0]=REVID;
	    EP1INBC = 1;
	    break;
	case 3: /* EP68fifoflags */
	    EP1INBUF[0]=EP68FIFOFLGS;
	    EP1INBC = 1;
	    break;
	case 4: /* EP2468stat */
	    EP1INBUF[0]=EP2468STAT;
	    EP1INBC = 1;
	    break;	    
	case 5: /* waveform sel */
	    EP1INBUF[0]=GPIFWFSELECT;
	    EP1INBC = 1;
	    break;	    
	case 6: /* flow state */
	    EP1INBUF[0]=FLOWSTATE;
	    EP1INBC = 1;
	    break;	    
	case 7: /* cb0 */
	    EP1INBUF[0]=GPIFTCB0;
	    EP1INBC = 1;
	    break;	    
    
	case 8: /* overflow status */
	    EP1INBUF[0]=bitOverflowCondition?1:0;
	    EP1INBC = 1;
	    break;
	default:
	    break;
    }	
    bitEP1INseen=0;
}

/* do a general FIFO reset after a reconnect with a device in
   an unknown state */
static void PrepareCleanState() {
    /* clear pending fifo stuff */
    fifo2reset();
    /* do proper reset of external FIFO */
    /*    transparent latch, disable sample, off extfifo */
    IOA = bmSampleInhibit | bmfifo_nCSB | bmNLatchEnable;
    bitDesiredInhibitStatus = 1;
    IFCONFIG = ifconfig_ports;

    /* zero port to get FIFO into a reset state; furthermore:
       BE=0 (little endian), FS0=0, FS1=1 (serial prog) */
    IOD = bmFIFO_FS1;
    
    /* in case FS1 is connected to ctl1 */
    GPIFCTLCFG = 0;     /* CMOS, non-tristatable */
    GPIFIDLECTL = 0x02; /* idle state for CTL0=ENB=0, CTL1=FS1=1 */
    
    bpstorage = bmDac_nSYNC | bmRfsrc_xtalsel;
    IOB = bpstorage;
    SpinDelay(10); /* for Clock generator to realize reset */
    bpstorage |= bmRfsrc_nPLOAD; /* load hardwired clock signals into PLL */
    IOB = bpstorage;

    /* carry out FIFO master reset; let MRS=0 sink in for a while.. */
    SpinDelay(40);
    /* latch setup info into FIFO with some hold time */
    IOD = bmFIFO_FS1 | bmFIFO_nMRS1 | bmFIFO_nMRS2 | bmFIFO_nWRB ; 

    /* FS1=1, FS0=0, take device out of reset and choose CY standard mode,
       configure port B for read (!!avod conflict by having CSB high before! */
    IOD = bmFIFO_FS1 | bmFIFO_nPRS | bmFIFO_nMRS1 | bmFIFO_nMRS2 
	| bmFIFO_nWRB | bmFIFO_BEnFWFT; 
    dpstorage = IOD;  /* keep for later */

    /* freeze data bits for later usage: switch latch to hold (sbit to 0) */
    IOA5 = 0 ;

    /* prepare GPIF in a reasonable state */
    GPIFIDLECS = 0; /* don't drive bus... */

    /* timer stuff */
    bitTimerSeen=0;
    flushcount=0;
    autoflushvalue=0; /* this means off */

    /* complete partial reset of timestamp; TODO: set read enable */
    ResetTimestamp();

    /* switch on Read enable */
    IOA6=1 ; /* disable CSB */
    IOB=bpstorage; IOD=dpstorage; /* restore values */
    IFCONFIG = ifconfig_ports;
    IOA5=1; /* transparent latch */
    dpstorage |= bmFIFO_nWRB; /* /W/RB to 1 */
    IOD=dpstorage;
    IOA5=0; /* latch data */
    /* IFCONFIG = ifconfig_active; switch back to FD bus ; not necessary here*/
    IOA6=0; /* enable chip select */

    /* prepare GPIF idle status into clean state */
    GPIFIDLECS = 0; /* don't drive data bus */
    IFCONFIG = ifconfig_active;

    bitGPIFrunning=0;  /* GPIF machine is switched off */
    bitEP1INseen=0;
    bitDoFlush=0;
    RFchoice = 0x790; /* due to HW reset */
    FIFOSerialProgram();
}

			       
/* Main parser routine for EP1OUT  commands */
void swallowEP1() {
    /* ToDo: Check checksum */
    /* get command */
    switch (EP1OUTBUF[1]) {
	case Reset_Timestampcard: /* TODO: reset_timestampcard */
	    HaltGPIFforLineaccess();
	    ResetTimestamp();
 	    ResumeGPIFafterLineaccess();
	    break;
	case SendDac: /* senddac */
	    HaltGPIFforLineaccess();
	    ShiftTarget = (EP1OUTBUF[3]<<8) | EP1OUTBUF[2];
	    SubmitDAC();
 	    ResumeGPIFafterLineaccess();
	    break;
	case InitDac: /* initdac */
	    HaltGPIFforLineaccess();
	    InitDAC(); /* send some magic words over...*/
 	    ResumeGPIFafterLineaccess();
	    break;
	case InitializeRFSRC: /* initializeRFSRC */
	    HaltGPIFforLineaccess();
	    bpstorage &= ~bmRfsrc_nPLOAD;
	    IOB = bpstorage;
	    bpstorage |= bmRfsrc_nPLOAD;
	    IOB = bpstorage;
	    ResumeGPIFafterLineaccess();
	    break;
	case Rf_Reference: /*  rf_reference */
	    HaltGPIFforLineaccess();
	    bpstorage &= ~bmRfsrc_xtalsel;
	    if (EP1OUTBUF[2]) bpstorage |= bmRfsrc_xtalsel;
	    IOB = bpstorage;
	    ResumeGPIFafterLineaccess();
	    break;
	case Send_RF_parameter: /*  sendrfcommand */
	    HaltGPIFforLineaccess();
	    ShiftTarget = (EP1OUTBUF[3]<<8) | EP1OUTBUF[2];
	    RFchoice = ShiftTarget; /* for later reference */
	    SubmitRFSRC();
	    ResumeGPIFafterLineaccess();
	    break;
	case Set_Inhibitline: /* setinhibitline */
	    IOA7 = 1; bitDesiredInhibitStatus = 1;
	    break;
	case Reset_Inhibitline: /* resetinhibit */
	    IOA7 = 0; bitDesiredInhibitStatus = 0;
	    break;
	case Set_calibration: /* setcalibration */
	    HaltGPIFforLineaccess();
	    dpstorage |= bmCalibrate;
	    IOD = dpstorage;
	    ResumeGPIFafterLineaccess();
	    break;
	case Clear_Calibration: /* clearcalibration */
	    HaltGPIFforLineaccess();
	    dpstorage &= ~bmCalibrate; /* Clear it */
	    IOD = dpstorage;
	    ResumeGPIFafterLineaccess();
	    break;
	case Initialize_FIFO: /* TODO: initialize internal FIFO */
	    /* stop everything */
	    fifo2reset();
	    break;
	case Stop_nicely: /* stopnicely */
	    StopFIFOAcquisition();
	    bitDoFlush =1; /* to empty current FIFO buffer */
	    bitGPIFrunning=0;
	    break;
	case Autoflush: /* TODO: autoflush */
	    autoflushvalue = EP1OUTBUF[2];
	    if(autoflushvalue) {
		flushcount=0;
		ET2=1; /* enable watchdog */
	    } else {
		ET2=0;
	    }
	   
	    break;
	case StartTransfer: /* start GPIF engine */
	    // fifo2reset();	    
	    bitGPIFrunning=1;
	    StartFIFOAcquisition();
	    break;
	case FreshRestart: /* restarts stuff after a reconnect */
	    GPIFABORT=0xff; /* terminate everything which is going on */
	    PrepareCleanState(); /* sort out the rest */
	    break;
	case RequestStatus:/* requests either status info, or one of
			      the descriptor packets at EP1 in; this is 
			      a bit baroque but there could be a pending
			      request */
	    ep1command = EP1OUTBUF[2];
	    bitEP1INseen=1;
	    break;
	case SlowCounterReset:  /* not sure if this is needed anywhere */
	    HaltGPIFforLineaccess();
	    bpstorage &= ~bmSlowcount_nSR; /* Clear it */
	    IOB = bpstorage;
	    SpinDelay(10); /* wait for some time */
	    bpstorage |= bmSlowcount_nSR; /* Set bit again */
	    IOB = bpstorage;
	    ResumeGPIFafterLineaccess();	    
	    break;
	case PartialFIFOreset:  /* to be on the safe side */
	    HaltGPIFforLineaccess();
	    dpstorage &= ~bmFIFO_nPRS; /* Clear it */
	    IOD = dpstorage;
	    SpinDelay(30); /* wait for some time */
	    dpstorage |= bmFIFO_nPRS; /* Set bit again */
	    IOD = dpstorage;
	    ResumeGPIFafterLineaccess();
	    break;
	default: /* TODO: stall EP? */
	    break;
    }
    /* re-arm input */
    EP1OUTBC = 0x40;
    bitEP1Seen=0;
}


void main() {
    initPorts(); /* initialize out port */
    initCPU();   /* initialize CPU stuff */
    configuration = 0;
    altsetting = 0;
    initUSB();   /* initiaize the USB machine */
    LoadWaveformGPIF();

    /* initialize autoflush option */
    SetupTimer0();
    bitTimerSeen=0;
    flushcount=0;
    autoflushvalue=0; /* this means off */

    /* TODO: initialize GPIF completely for extFIFO->intFIFO*/

    EA = 1; /* enable irqs */

    /* It is really sick that this is needed at this stage. We need to
       initialize the ADCs in order for the TTL portion to see some clock
       in order to load the external FIFO with its overflow values. There has
       to be a nicer way..... 
       for the time being, let's assume we are in ports mode here and do the
       DAC spiel....
    */
    IOA6=1 ; /* disable CSB */
    IOB=bpstorage; IOD=dpstorage; /* restore values */
    IFCONFIG = ifconfig_ports;
    IOA5=1; /* transparent latch */

    InitDAC();InitDAC2();

    IOA5=0; /* latch data */
    GPIFIDLECS = 0; /* don't drive data bus */
    ifconfig_active = ifconfig_gpif;  /* allow GPIF data to bus */
    IFCONFIG = ifconfig_active;


    /* ReEnumberate();  re-enumerate */
    ReEnumberate();

    /* conduct a full FIFO reset and program the AE flag */
    //FIFOupperwatermark = 12288;  /* about 4 kbyte buffer for a 7C43683 chip*/
    //FIFOupperwatermark = 6144;  /* this is for a 8k FIFO, e.g. IDT723673 */
    FIFOupperwatermark = 3072;  /* this is used for a smaller FIFO, 7C43643 */
    FIFOSerialProgram();


    /* complete partial reset of timestamp; TODO: set read enable */
    ResetTimestamp();

    /* switch on Read enable */
    IOA6=1 ; /* disable CSB */
    IOB=bpstorage; IOD=dpstorage; /* restore values */
    IFCONFIG = ifconfig_ports;
    IOA5=1; /* transparent latch */
    dpstorage |= bmFIFO_nWRB; /* /W/RB to 1 */
    IOD=dpstorage;
    IOA5=0; /* latch data */
    /* IFCONFIG = ifconfig_active; switch back to FD bus ; not necessary here*/
    IOA6=0; /* enable chip select */

    /* prepare GPIF idle status into clean state */
    GPIFIDLECS = 0; /* don't drive data bus */
    ifconfig_active = ifconfig_gpif;  /* allow GPIF data to bus */
    IFCONFIG = ifconfig_active;
    
    bitGPIFrunning=0;  /* GPIF machine is switched off */
    hitcnt=0; oldcnt=0; /* for autoflush option */

    /* ------------ here we should have reached an idle state ------- */

    /* main loop: wait forever */
    for (;;) {
	if (bitSUDAVSeen) doSETUP();  /* Handle SUDAV Events */
	
	if (bitEP1Seen) swallowEP1(); /* Process command on EP1 */

	if (bitEP1INseen) fillEP1();  /* return status variable */

	if (bitTimerSeen) { /* autoflush option */
	    bitTimerSeen=0; /* clear bit... */
	    flushcount--;
	    if (!flushcount) {/* decrement counter */
		flushcount = autoflushvalue; /* ...and reload */
		/* criterion for flushing need */
		newcnt = EP2BCL + (EP2BCH<<8);
		if ((oldcnt == newcnt) && (EP2CS & bmEPEMPTY)) {
		    hitcnt++; /* how often has that condition been seen ?*/
		} else { 
		    hitcnt=0;
		}
		oldcnt=newcnt;

                /* force flush */
		if (hitcnt>1) {
		    bitDoFlush=1; 
		    hitcnt=0;
		}
	    }
	}
	if (bitDoFlush) { /* committ current buffer to output */
	    /* switch off GPIF */
	    INPKTEND = 0x02; /* do commit */
	    /* This is slightly dodgy as it could happen between two
	       events... */
	    bitDoFlush=0;
	}

	/* switch inhibit line off again */
	/* switch overflow cond off */
	if (bitOverflowCondition) {
	    if (!IOA4) {
		bitOverflowCondition = 0;
		if (!bitDesiredInhibitStatus) IOA7=0;
	    }

	}

	/* switch inhibit line on */
	if (IOA4 ) { /* almost empty flag */ 
	    if (!bitOverflowCondition) {
		bitOverflowCondition = 1;
		IOA7 = 1; /* inhibit sampling */
	    }
	}

    }
    
}
