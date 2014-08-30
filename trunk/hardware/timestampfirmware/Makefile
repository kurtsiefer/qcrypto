OPCS = --model-small

TRG=tp8
HEADERFILES = fx2regs_c.h fifobithelpers.h

all: $(TRG).ihx

$(TRG).ihx: $(TRG).c $(HEADERFILES)
	sdcc $(OPCS) $(TRG).c
# Make sure that the following pointers start on an even address
# by (un)commenting the xuxu variables. This is dirty...
	grep "_Descriptors:" $(TRG).rst
	grep "_Descriptors2:" $(TRG).rst
	grep "_StringDescriptors:" $(TRG).rst

