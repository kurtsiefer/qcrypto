/* timetag_io2.c:  Part of the quantum key distribution software, and
                   companion for the readevents program. This code
		   contains the hardware near code for the USB version of
		   the unit Version as of 20071228.

 Copyright (C) 2005-2008 Christian Kurtsiefer, National University
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

   companion to timestamp3.c, contains close-to hardware routines to 
   talk to the timestamp card.  This code for the USB timestamp card is 
   based on previous code interfacing to the timestamp card attached to a 
   nudaq PCI7200 parallel input card. 

*/


#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#include "timetag_io2.h"
#include "usbtimetagio.h"

/********************************************************************/
/*  DAC related code. The handle argument refers to the usb device
    see data sheet for AD5318 from Analog Devices for bit pattern
    definition for serial loading. 
    
    Part of the low level code is now in the firmware...
 */


/* function to initialize the DAC */
int initialize_DAC(int handle) {
    ioctl(handle, InitDac); /* how to handle errors? */
    return 0;
}

/* function to set a DAC port to a certain 12-bit value. returns 0 on
   success or an error code. least 2 (4) significant bits in data are ignored
   for the 10 bit (8 bit) converter AD5318 (AD5308).
*/
int set_DAC_channel(int handle, int channel, int value){
  int retval;
  if ((value<0 )|| (value > 0xfff)) return -1; /* value out of range */
  if ((channel<0) || channel>7) return -1;  /* channel out of range */
  /* printf("calling code %d with argument %d\n",SendDac,
     (((channel & 7)<<12) | (value & 0xfff))); */
  retval=ioctl(handle, SendDac, (((channel & 7)<<12) | (value & 0xfff)));
  /* printf("retval: %d, errno:%d\n",retval,errno); */
  return retval;
}

/*******************************************************************/

/********************************************************************/
/*  rfsource related code. There, an internal or external source can
    be choosen, and the frequency can be set. details can be found in the
    NBC12430 data sheet from ON semiconductor.

    Lowlevel stuff moved to firmware....
 */

/* initialize synthesizer chip by ploading and choosing the internal xtal */
int initialize_rfsource(int handle){
    ioctl(handle, InitializeRFSRC); /* how to handle errors? */
    return 0;
}

/* choose internal clock reference */
int rfsource_internal_reference(int handle){
    return ioctl(handle, Rf_Reference, 1);
};
/* choose external */
int rfsource_external_reference(int handle){
    return ioctl(handle, Rf_Reference, 0);
};
/* transmit testregister t, output divider n, main divider m bits to the
   rf source chip; returns 0 on success */
int _rfsource_set_registers(int handle, int t, int n, int m){
    int u; 
    if (t & ~7) return -1; /* t range overflow */
    if (n & ~3) return -1; /* output divider overflow */
    if (m & ~0x1ff) return -1; /* main divider overflow */
    
    /* assemble data word and transmit the 14 bits to the usb device */
    u=((t & 7)<<11) | ((n & 3)<<9) | (m & 0x1ff);
    ioctl(handle, Send_RF_parameter, u); /* error treatment?? */
    return 0;
}

/* optimize frequency assuming a reference freq. returns exact freq or <0
   on error. All Frequencies are given in kilohertz. */
int adjust_rfsource(int handle, int ftarget, int fref){
  int np; /* out_divider power; division ratio 2,4,8,1 for np=0,1,2,3 finally*/
  int m; /* main divsion ratio */
  int tmp;
  if (fref<10000 || fref>20000) return -5; /* reference out of range */
  if (ftarget <50000) return -3;/* frequency below VCO capability */
  if (ftarget>800000) return -2; /* frequency exceeds VCO capability */

  /* calculate raw division power to keep VCO between 400 and 800 MHz */
  tmp = (800000/ftarget);
  if (tmp>16) return -3; /* frequency below VCO capability */
  for (np=1;tmp>>np;np++); /* np = 1,2,3,4 for ratios 1,2,4,8*/

  /* calculate main divider setting */
  m=(ftarget <<(np-1))/(fref>>3); /* should give right main divider ratio */
  if (m<1 || m>0x1ff) return -4; /* main divider out of range */
  /* send this to the chip, test mode switched off;
     correction to np in the chip; ratio 2,4,8,1 for n_value=0,1,2,3 */
  if (_rfsource_set_registers(handle, 0,(np+2)&3,m)) return -1; /* some err */
  /* calculate generated frequency in kilohertz; true frequency may be off
   up to a kHz due to rounding */
  return ((1<<np)*fref*m)>>4;
}
/*******************************************************************/


/*******************************************************************/
/* routines to enable sampling and calibration */
void set_inhibit_line(int handle, int state) {
    ioctl(handle, state?Set_Inhibitline:Reset_Inhibitline);
}
void set_calibration_line(int handle, int state) {
    ioctl(handle,state?Set_calibration:Clear_Calibration);
}

/*******************************************************************/


/*******************************************************************/
/* initialize FIFO */
/* choose configurtion as little endian conversion & CY standard mode */
void Reset_gadget(int handle) {
    ioctl(handle, FreshRestart); /* ext FIFO reset */
}
void initialize_FIFO(int handle) {
    ioctl(handle, PartialFIFOreset); /* external FIFO reset */
    ioctl(handle, Initialize_FIFO); /* EZ-USB fifo reset */
}
#ifdef PART_RES_PRESENT
void fifo_partial_reset(int handle) {
    ioctl(handle, Partial_FIFOReset); /* ext fifo reset - not defined yet. */
}
#endif

void reset_slow_counter(int handle) {
    ioctl(handle,Reset_Timestampcard); 
}

void usb_flushmode(int handle, int mode) {
    ioctl(handle,Autoflush, mode& 0xff);
}

/*******************************************************************/


/*******************************************************************/
/* routines to start/stop DMA */
void start_dma(int handle) {
    ioctl(handle, Start_USB_machine); /* in device driver */
    ioctl(handle, StartTransfer);  /* in firmware */
}

void stop_dma(int handle) {
    ioctl(handle,Stop_nicely);
    // usleep(100000); /* wait for last packet to arrive */
    ioctl(handle, Stop_USB_machine);
}

/*******************************************************************/





