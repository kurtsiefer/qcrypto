/* usbtimetagio.h:  Part of the quantum key distribution software, and
                    companion for the readevents program. This code
		    contains definitions used by the readevens program and the
		    firmware in the EZ-usb chip.
		    Version as of 20071228

 Copyright (C) 2006-2007, 2010 Christian Kurtsiefer, National University
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

#define  _Reset_Timestampcard 1    /* needs no argument */
#define  _SendDac             2    /* takes a 16bit value as argument */
#define  _InitDac             3    /* initialize DAC, no args  */
#define  _InitializeRFSRC     4    /* initialize RF PLL, noargs */
#define  _Rf_Reference        5    /* selects the internal or ext ref src */
#define  _Send_RF_parameter   6    /* PLL programming stuff, takes 16 bit wrd */
#define  _Set_Inhibitline     7    /* switch off data taking */
#define  _Reset_Inhibitline   8    /* allow data taking. no args */
#define  _Set_calibration     9    /* set calibration line (i.e. disables it) */
#define  _Clear_Calibration   10   /* reset calibration line (enables cal) */
#define  _Initialize_FIFO     11   /* clears EZ internal FIFO */
#define  _Stop_nicely         12   /* switches off the GPIF cleanly */
#define  _Autoflush           13   /* allow submission of urbs after a 
				     define multiples of 10 msec */
#define  _StartTransfer       14   /* start GPIF engine */
#define  _FreshRestart        15   /* restarts timestamp card into a
				     fresh state after a reconnect */
#define  _RequestStatus       16   /* requests either status info, or one of
				     the descriptor packets at EP1 in */
#define  _SetWarningwatermark 17   /* set the FIFO warning watermark */
#define  _SlowCounterReset    18   /* reset slow counter */
#define  _PartialFIFOreset    19   /* reset external FIFO */

/* firmware installation tool. */
#define  _WriteBootEEPROM     99   /* sets or unsets the boot EEPROM region */


/* internal commands for the driver to handle the host driver aspects */
#define  _Start_USB_machine   100  /* prepare DMA setup */
#define  _Stop_USB_machine    101  /* end data acquisition */
#define  _Get_transferredbytes 102 /* how many bytes have been transferred */
#define  _Reset_Buffering     103  /* give local buffer a restart */
#define  _Get_errstat         104  /* read urb error status */


/* The following is an attempt to make the ioctl commands compliant to the
   recommendation for ioctl numbers in a linux system and maintain the one-byte
   size for commands sent over the USB channel since it appears that the
   single byte ioctls get swallowed by the OS otherwise. So for now, the
   header file does need to be preceeded by a compiler statement to define
   "firmware" if the header file is used to generate firmware code. */

#ifdef firmware
#define IOCBASE 0x00 /* we stay bytewise */
#define IOCBASEW 0x00
#define IOCBASEWR 0x00
#else
#include <linux/ioctl.h>
#define IOCBASE 0xaa00
#define IOCBASEW 0xaa00
#define IOCBASEWR 0xaa00
#endif

/* here are the definitions which restore the values for both firmware and
   driver/application domain */

#define  Reset_Timestampcard ( _Reset_Timestampcard | IOCBASE)
#define  SendDac             ( _SendDac | IOCBASEW )
#define  InitDac             ( _InitDac | IOCBASE )
#define  InitializeRFSRC     ( _InitializeRFSRC | IOCBASE )
#define  Rf_Reference        ( _Rf_Reference | IOCBASEW )
#define  Send_RF_parameter   ( _Send_RF_parameter | IOCBASEW )
#define  Set_Inhibitline     ( _Set_Inhibitline | IOCBASE )
#define  Reset_Inhibitline   ( _Reset_Inhibitline | IOCBASE )
#define  Set_calibration     ( _Set_calibration | IOCBASE )
#define  Clear_Calibration   ( _Clear_Calibration | IOCBASE )
#define  Initialize_FIFO     ( _Initialize_FIFO  | IOCBASE )
#define  Stop_nicely         ( _Stop_nicely  | IOCBASE )
#define  Autoflush           ( _Autoflush | IOCBASEW )
#define  StartTransfer       ( _StartTransfer | IOCBASE )
#define  FreshRestart        ( _FreshRestart | IOCBASE )
#define  RequestStatus       ( _RequestStatus | IOCBASEWR )
#define  SetWarningwatermark ( _SetWarningwatermark | IOCBASEW )
#define  SlowCounterReset    ( _SlowCounterReset | IOCBASE )
#define  PartialFIFOreset    ( _PartialFIFOreset | IOCBASE )

#define  WriteBootEEPROM     ( _WriteBootEEPROM | IOCBASEW )

#define  Start_USB_machine   ( _Start_USB_machine | IOCBASE )
#define  Stop_USB_machine    ( _Stop_USB_machine | IOCBASE )
#define  Get_transferredbytes ( _Get_transferredbytes | IOCBASEWR )
#define  Reset_Buffering     ( _Reset_Buffering | IOCBASE )
#define  Get_errstat         ( _Get_errstat | IOCBASEWR )
