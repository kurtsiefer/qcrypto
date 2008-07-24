/* usbtimetagio.h:  Part of the quantum key distribution software, and
                    companion for the readevents program. This code
		    contains definitions used by the readevens program and the
		    firmware in the EZ-usb chip.
		    Version as of 20071228

 Copyright (C) 2006-2007 Christian Kurtsiefer, National University
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


   definitions of ioctl commands for the usb-timetag card executed by 
   the firmware in the card interface  */

#define  Reset_Timestampcard 1    /* needs no argument */
#define  SendDac             2    /* takes a 16bit value as argument */
#define  InitDac             3    /* initialize DAC, no args  */
#define  InitializeRFSRC     4    /* initialize RF PLL, noargs */
#define  Rf_Reference        5    /* selects the internal or ext ref src */
#define  Send_RF_parameter   6    /* PLL programming stuff, takes 16 bit wrd */
#define  Set_Inhibitline     7    /* switch off data taking */
#define  Reset_Inhibitline   8    /* allow data taking. no args */
#define  Set_calibration     9    /* set calibration line (i.e. disables it) */
#define  Clear_Calibration   10   /* reset calibration line (enables cal) */
#define  Initialize_FIFO     11   /* clears EZ internal FIFO */
#define  Stop_nicely         12   /* switches off the GPIF cleanly */
#define  Autoflush           13   /* allow submission of urbs after a 
				     define multiples of 10 msec */
#define  StartTransfer       14   /* start GPIF engine */
#define  FreshRestart        15   /* restarts timestamp card into a
				     fresh state after a reconnect */
#define  RequestStatus       16   /* requests either status info, or one of
				     the descriptor packets at EP1 in */
#define  SetWarningwatermark 17   /* set the FIFO warning watermark */
#define  SlowCounterReset    18   /* reset slow counter */
#define  PartialFIFOreset    19   /* reset external FIFO */

/* firmware installation tool. */
#define  WriteBootEEPROM     99   /* sets or unsets the boot EEPROM region */


/* internal commands for the driver to handle the host driver aspects */
#define  Start_USB_machine   100  /* prepare DMA setup */
#define  Stop_USB_machine    101  /* end data acquisition */
#define  Get_transferredbytes 102 /* how many bytes have been transferred */
#define  Reset_Buffering     103  /* give local buffer a restart */
#define  Get_errstat         104  /* read urb error status */
