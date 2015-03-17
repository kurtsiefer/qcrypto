# Makefile for the usb timestamp card. For multiple SuSE versions. Currently
# generates the drivers and uploads different hotpluggers
#
# ToDo: - should allow to choose different install directories than
#	  the source directories.
#	- Should use a cleaner install routine
# 
# current status: start rewriting 6.11.06 christian Kurtsiefer


# directory for the driver for the local OS version
localdir=$(subst /,\/,$(PWD))
version="2.6"
sourcedir=$(PWD)/2.6
loaderdir=hotplug
loadersrc1=$(loaderdir)/udevsrc
loadersrc2=$(loaderdir)/hotplgsrc
loadertarget1=$(loaderdir)/60-timestamp.rules
loadertarget2=$(loaderdir)/t5.hotplug
udevscript1="s/users/$(shell id -gn)/g"
udevscript2="s/DRIVERPATH/$(localdir)\/2.6/g"

all: driver $(loadertarget1) $(loadertarget2)

# execute version-specific makefile
.PHONY: driver
driver:	$(loadertarget1) $(loadertarget2)
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(sourcedir)

$(loadertarget1): $(loadersrc1)
	sed -e $(udevscript1) -e $(udevscript2) $(loadersrc1) >$(loadertarget1)

$(loadertarget2): $(loadersrc2)
	cat $(loadersrc2) | sed "s/DRIVERPATH/$(localdir)\/2.6/g" >$(loadertarget2)


.PHONY: clean
clean:	
	rm -f $(loadertarget1)
	rm -f $(loadertarget2)
	rm -f 2.6/*.o 2.6/*.mod.* 2.6/*.ko 2.6/.d*
	rm -fr 2.6/.tmp*

udev: 	driver $(loadertarget1)
	sudo $(MAKE) -C /lib/modules/`uname -r`/build M=$(sourcedir) modules_install
	sudo /sbin/depmod -a
	sudo cp $(loadertarget1) /etc/udev/rules.d/

hotplugd: driver $(loadertarget2)
	sudo cp $(loadertarget2) /etc/hotplug.d/usb/
	sudo chmod 744 /etc/hotplug.d/usb/t5.hotplug
