# Makefile for the usb timestamp card. For multiple SuSE versions. Currently
# generates the drivers and uploads different hotpluggers
#
# ToDo: - should allow to choose different install directories than
#	  the source directories.
#	- Should use a cleaner install routine
# 
# current status: start rewriting 6.11.06 christian Kurtsiefer
#                 cleanup for 4.12 kernel 14.7.2018    

# directory for the driver
localdir=$(subst /,\/,$(PWD))
sourcedir=$(PWD)/driver
loaderdir=hotplug
loadersrc1=$(loaderdir)/udevsrc
loadertarget1=$(loaderdir)/60-timestamp.rules
udevscript1="s/users/$(shell id -gn)/g"

all: driver $(loadertarget1) $(loadertarget2)

# execute version-specific makefile
.PHONY: driver
driver:	$(loadertarget1)
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(sourcedir)

$(loadertarget1): $(loadersrc1)
	sed -e $(udevscript1) $(loadersrc1) >$(loadertarget1)

.PHONY: clean
clean:	
	rm -f $(loadertarget1)
	rm -f driver/*.o driver/*.mod.* driver/*.ko driver/.d*
	rm -fR driver/.tmp*
	rm -f driver/.b* driver/.usb* driver/modu* driver/Modu*

udev: 	driver $(loadertarget1)
	sudo $(MAKE) -C /lib/modules/`uname -r`/build M=$(sourcedir) modules_install
	sudo /sbin/depmod -a
	sudo cp $(loadertarget1) /etc/udev/rules.d/
