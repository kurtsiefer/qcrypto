/* ffind.c :    Part of the quantum key distribution software (auxiliary)
                for identifying initial timing difference. This is for
		tesing the algorithm mainly, timing datat should be provided
		in plain ascii text, one value per line
                Description see below. Version as of 20070101

 Copyright (C) 2005 Christian Kurtsiefer, National University
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

progran to find the time difference between two traces.

usage: ffind file1 file2

output: time difference in 1/8 ns, accurate to 2 nsec, service info

file format input : plain decimal time in 1/8 nsec */
 


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <fftw3.h>

/* some parameters */
#define FNAMBUFFERLEN 200 /* file name buffer length */
#define BUF_BITWIDTH 17  /* length of individual buffers */
#define ZHS (1<<BUF_BITWIDTH)
#define FRES_ORDER 1
#define FINE_RES (1<<FRES_ORDER) /* fine resolution in nsec */
#define CRES_ORDER 11
#define COARSE_RES (1<<CRES_ORDER) /* coarse resolution in nsec */


/* error handling */
char *errormessage[] = {
    "No error.",
    "argument number not 2", /* 1 */
    "error opening file 1",
    "error opening file 2",
    "cannot load first value from file 1", /* 4 */
    "cannot load first value from file 2",/* 5 */
    "cannot malloc int buffer",

    
};
/* buffer for summation register */
int *buf1_fast, *buf1_slow, *buf2_fast, *buf2_slow;

/* buffer for fourier transforms */
fftw_complex *f1, *f2 ;/* transform fields */
fftw_plan plan1, plan2, plan3; /* ftrafo plans */ 

/* fill complex field with int filed, do transform and retrun max/sigma */
void findmax(int *buf1, int *buf2, double* maxval, double *sigma, 
	     double* mean,int *pos,int size,int ecnt1, int ecnt2) {
    int i; /* counter index */
    double ai,ar,br,bi; /* temporary variables */
    double sx,sxx;
    int maxpos;

    /* clear double buffers / transfer int to double buffers */
    ar=((double)ecnt1)/size; /* to get mean at zero */
    br=((double)ecnt2)/size;
    for (i=0;i<size;i++){
	f1[i][0]=(double)buf1[i]-ar;f1[i][1]=0.;
	f2[i][0]=(double)buf2[i]-br;f2[i][1]=0.;
    }
    /* do forward transformations */
    fftw_execute(plan1);  fftw_execute(plan2); 
    /* do conjugate and multiplication into array 1 */
    for (i=0;i<size;i++){
	ar=f1[i][0];ai=f1[i][1]; br=f2[i][0];bi=f2[i][1];
	f1[i][0]=ar*br+ai*bi;f1[i][1]=ar*bi-ai*br;
    }
    /* do do backtransform */
    fftw_execute(plan3);
    /* evaluate max, stddev and mean */
    *maxval=0.;maxpos=0;sxx=0;sx=0.;
    for (i=0;i<size;i++){
	ar=f1[i][0];if (ar > *maxval) {maxpos=i; *maxval=ar;}
	sx+=ar;sxx+=(ar*ar);
    }
    /* return values properly back */
    *mean = sx / size;
    *sigma = sqrt(sxx/size- (*mean) * (*mean));
    *pos=maxpos;
}


int emsg(int code) {
  fprintf(stderr,"%s\n",errormessage[code]);
  return code;
};
/* proceure to fill the fast and slow folded event time functions. Fh
   contains the source file handle, the buffers are of length 2^order
   and the targeted bin width is 2^fres and 2^s_res, in multiples
   of1/8 nsec */
void fill_periodicals(FILE *fh, int *buf_fast, int fres, int *buf_slow,
		      int sres, int order, int *ecnt) {
    long long int intime;
    long long int mask = (1<<(order))-1;
    while (EOF!=fscanf(fh,"%lld",&intime)) {
	buf_fast[(int)(mask & (intime>>fres))]++;
	buf_slow[(int)(mask & (intime>>sres))]++;
	*ecnt +=1;
    }
}

int main(int argc, char *argv[]){
    char fname1[FNAMBUFFERLEN],fname2[FNAMBUFFERLEN];  /* file name buffers */
    FILE *fh1, *fh2; /* input file handles */
    int ecnt1,ecnt2; /* contains number of events in files 1,2 */
    int pos_s, pos_f; /* position of maximum */
    double maxval_s, maxval_f, sigma_s, sigma_f, mean_s, mean_f; /* results */

    long long int t0,timediff; /* final timedifference in 1/8 nsec */
    if (argc!=3) return -emsg(1);
    strncpy(fname1,argv[1],FNAMBUFFERLEN);fname1[FNAMBUFFERLEN]=0;
    strncpy(fname2,argv[2],FNAMBUFFERLEN);fname2[FNAMBUFFERLEN]=0;

    /* printf("stage1\n"); */
    
    /* prepare integer buffers */
    buf1_fast=(int*)calloc(ZHS*4,sizeof(int));
    if (!buf1_fast) return -emsg(6);
    buf1_slow=&buf1_fast[ZHS];buf2_fast=&buf1_slow[ZHS];
    buf2_slow=&buf2_fast[ZHS];

    /* printf("stage 2\n"); */

    /* prepare files into buffer */
    ecnt1=0;
    fh1=fopen(fname1,"r"); if (!fh1) return -emsg(2);
    fill_periodicals(fh1,buf1_fast,FRES_ORDER+3,buf1_slow,CRES_ORDER+3,
		     BUF_BITWIDTH, &ecnt1);
    fclose(fh1);

    /* printf("stage 2a; ecnt1= %d\n",ecnt1); */

    ecnt2=0;
    fh2=fopen(fname2,"r"); if (!fh2) return -emsg(3);
    fill_periodicals(fh2,buf2_fast,FRES_ORDER+3,buf2_slow,CRES_ORDER+3,
		     BUF_BITWIDTH, &ecnt2);
    fclose(fh2);
    /* printf("stage 3, ecnt2=%d\n",ecnt2); */

    /* prepare fourier transform */
    f1 = fftw_malloc(sizeof(fftw_complex) * ZHS);
    f2 = fftw_malloc(sizeof(fftw_complex) * ZHS);
    
    plan1 = fftw_plan_dft_1d(ZHS, f1, f1, FFTW_FORWARD, FFTW_ESTIMATE);
    plan2 = fftw_plan_dft_1d(ZHS, f2, f2, FFTW_FORWARD, FFTW_ESTIMATE);
    plan3 = fftw_plan_dft_1d(ZHS, f1, f1, FFTW_BACKWARD, FFTW_ESTIMATE);
    /* printf("stage 4\n"); */
   
    /* do job for slow array */
    findmax(buf1_slow, buf2_slow, &maxval_s, &sigma_s, &mean_s,&pos_s,
	    ZHS,ecnt1,ecnt2);
    /* do job for fast array */
    findmax(buf1_fast, buf2_fast, &maxval_f, &sigma_f, &mean_f,&pos_f,
	    ZHS,ecnt1,ecnt2);

    /* printf("stage 5\n"); */

    /* consolidate time difference from fast/slow values */
    if (pos_s & (ZHS>>1)) pos_s |= (-ZHS); /* do sign extend */
    t0=pos_s*COARSE_RES;
    timediff=(long long int)((pos_f-t0/FINE_RES) & (ZHS-1));
    if (timediff & (ZHS>>1)) timediff |= (-ZHS); /* do sign extend */
    timediff *=FINE_RES;  
    timediff +=t0;
    timediff *=8; /* correction to 1/8 nsec */
    /* printf("stage 6\n"); */

    /* do washup for fft arrays */
    fftw_destroy_plan(plan1);fftw_destroy_plan(plan2);fftw_destroy_plan(plan3);
    /* do washup for buffers */
    fftw_free(f1);  fftw_free(f2); free(buf1_fast);
    /* output values */
    printf("difference: %lld, sig_f: %f, sig_c:%f\n",
	   timediff, maxval_f/sigma_f,maxval_s/sigma_s);
 
    return 0;

}
