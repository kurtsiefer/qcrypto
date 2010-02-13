OPCS = --model-small

TRG=tp8
HEADERFILES = fx2regs_c.h fifobithelpers.h

all: $(TRG).ihx

$(TRG).ihx: $(TRG).c $(HEADERFILES)
	sdcc $(OPCS) $(TRG).c
	grep "Descriptors:" $(TRG).rst
	grep "Descriptors2:" $(TRG).rst

