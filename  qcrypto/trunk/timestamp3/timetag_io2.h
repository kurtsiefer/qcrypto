/* timetag_io2.h:  Part of the quantum key distribution software, and
                   companion for the readevents program. This code
		   contains the header for code near to hardware.
		   Version as of 20071228

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

*/

/* declaration of functions in timetag_io.c */
int initialize_DAC(int handle);
int initialize_DAC(int handle);
int set_DAC_channel(int handle, int channel, int value);
int initialize_rfsource(int handle);
int rfsource_internal_reference(int handle);
int rfsource_external_reference(int handle);
int _rfsource_set_registers(int handle, int t, int n, int m);
void usb_flushmode(int handle, int mode);
int adjust_rfsource(int handle, int ftarget, int fref);
void set_inhibit_line(int handle, int state);
void set_calibration_line(int handle, int state);
void initialize_FIFO(int handle);
void fifo_partial_reset(int handle);
void start_dma(int handle);
void stop_dma(int handle);
void reset_slow_counter(int handle);
void Reset_gadget(int handle);


