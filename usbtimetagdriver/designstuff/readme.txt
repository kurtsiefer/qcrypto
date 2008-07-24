this is a collection of ideas for the usb driver.

USB ids: temporarily I need to pick one which is (hopefully) not used.

Choice: cypress as manufacturer, (VID: 04b4), choose device code (PID: 1234)

configurations: want only one to start with; perhaps this can distinguish
between full speed and high speed modes (actually need both...)


I keep it simple and choose only one interface to keep the switching overhead
low.

alternate settings: choose two, "0" for device identification, "1" for more
serious communication. Upon opening a driver, the alternate setting should be
set to "1".

endpoints: 0 is the standard control endpoint, 1 will be used for setting the
control lines in a hopefully lean manner. Endpoint 2 will be the high speed
transfer buffer for FIFO data.

device class:    ff (venor-specific class)
device subclass: ff (vendor-specific subclass)
device protocol: ff (vendor-specific protocol)

Interface class:  (no need?)
Interface subclass:
interface protocol:

simple routines  to try communication with usb: usb_bulk_msg and
usb_control_msg

A first test device should implement endpoints 0 for the standard responses,
and endpoint 1 or data output. Can I configure ep1 only as out? First step
would be to copy the first byte of a transfer to the output.


--
Try to implement new device structure: Registering a device etc.
* try to get a char device number (p45): alloc_chrdev_region(....)
*unregister_chrdev_region(....) see example p 48

* char device registration: see p 55

* creati0n of a char device from a dynamic major use script on p 48. Does this
  also work for usb devices?

the first test device driver should only offer a simple char device which has
one ioctl command to send out a packet to the EP1 containing this one byte.

The application should look for that device, and send stuf to it.

What stuff needs to be done to register a USB device driver? Does that simply
work the same way as a char device driver?

How does a driver get told that a USB device of given identity was inserted?
How does it get told that something is disconnected?

USB device driver issues:

almost like a PCI device, specifies a number of devices to be handled and can
register a USB device, which in turn can be used to create a dynamical device
entry.

