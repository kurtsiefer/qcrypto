/* fifobithelpers.h:
   helper file for the bit values in the various port registes of the 
   EZ-USB chip interfacing the timestamp card.

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

   to be used by the firmware; most definitions make sense in context with the
   chip descriptions. There are:
   - external FIFO: CY7C43683
   - DAC: AD5318
   - RFSRC: NBC12430
   The rest should be understood together with the circuit diagrams of the
   main timestamp unit.
   fixed: got calibrate/FWFT lines exchanged

*/

/* entries for lines connected to port A */
#define bmSampleInhibit 0x80   /* bit PA7 */
#define bmfifo_nCSB 0x40
/* latching lines */
#define bmNLatchEnable 0x20
#define bmFIFOAlmostEmptyFlag 0x10


/* secondary definitions for port B */
#define bmSlowcount_nSR 0x80   /* slow counter reset line, active low */
#define bmRfsrc_xtalsel 0x20   /* 0: external, 1: internal ref */
#define bmRfsrc_nPLOAD  0x10   /* parallel load line */
#define bmRfsrcDac_serdata 0x8 /* serial data line */
#define bmRfsrc_SLOAD 0x4      /* serial load line */
#define bmDac_nSYNC   0x2      /* DAC serial load line */
#define bmRfsrcDac_serclk 0x1  /* serial clock */

/* secondary definitions for port D */
#define bmFIFO_FS1 0x80        /* init line / serial enable */
#define bmFIFO_nPRS 0x40       /* partial reset */
#define bmFIFO_nMRS1 0x20      /* Master reset 1 */
#define bmFIFO_FS0  0x10       /* init line / serial data */
#define bmFIFO_nMRS2 0x8       /* Master reset 2 */
#define bmFIFO_nWRB  0x4       /* /W/R portB line */
#define bmFIFO_BEnFWFT 0x2     /* init line */
#define bmCalibrate  0x1       /* Calibration line */
