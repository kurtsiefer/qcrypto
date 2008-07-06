# this makefile containes only the device driver itself. At the moment
# just a test suite 

# kernel 2.6 style


ifneq ($(KERNELRELEASE),)
obj-m :=  usbtimetag.o

else
KDIR	:= /lib/modules/`uname -r`/build
PWD		:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
endif