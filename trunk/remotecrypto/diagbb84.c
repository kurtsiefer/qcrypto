/* diagbb84.c : Part of the quantum key distribution software for extracting
                the length of a t3 binary file. Description see below.
		Version as of 20070101
 identifying identifying
                temporal coincidences, tracking clock differences and
                initial key sifting on the high count rate side.
                temporal coincidences, tracking clock differences and
                initial key sifting on the high count rate side.
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

   this program digests a t3 binary file and tries to extract a length of a
   BB84 raw key file.
   
   usage: diagbb84 filename

   the program ejects three numbers: the filetype of the BB84 subtype,
   the number of bits per entry and the number of entries. If the type is
   not a BB84 raw bit file, all three numbers are 0.
   

*/

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#define FNAMELENGTH 200  /* length of file name buffers */
#define FNAMFORMAT "%200s"   /* for sscanf of filenames */
#define DEFAULT_OUTMODE 0 /* supply formatted output */

#define RAW3i_SIZE 1500000  /* more than enough? */


typedef struct header_3 {/* header for type-3 stream packet */
    int tag;
    unsigned int epoc;
    unsigned int length;
    int bitsperentry; 
} h3;

#define TYPE_3_TAG 3
#define TYPE_3_TAG_U 0x103



char *errormessage[] = {
  "No error.",
  "Error reading file/directory name for type-7 input packets.", /* 1 */
  "cannot malloc input buffer.",
  "canot open input file",
  "cannot get header",
  "error reading file (nothing there)", /* 5 */
};
int emsg(int code) {
  fprintf(stderr,"%s\n",errormessage[code]);
  return code;
};


int main (int argc, char *argv[]) {
    char fname[FNAMELENGTH]={""}; /* stream files */
    int handle, retval;
    struct header_3 h;


    /* get filename*/
    if (1!=sscanf(argv[optind],FNAMFORMAT,fname)) return -emsg(1);
    
    /* get file header */
    handle=open(fname,O_RDONLY);
    if (-1==handle) return -emsg(3);

    retval=read(handle,&h,sizeof(h));
    if (retval!=sizeof(h)) return -emsg(4);
    if (!retval) return 5; 

    /* printf("length: %d\n",h->length); */

    if ((h.tag!=TYPE_3_TAG) && (h.tag!=TYPE_3_TAG_U))  {
	printf("0 0 0\n");
    } else {
	printf("%d %d %d \n",h.tag,h.bitsperentry,h.length);
    }
    return 0;

}
