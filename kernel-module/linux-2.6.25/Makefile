obj-m    := stubl.o
KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

MODULE_NAME := stubl.ko
INSTALL_PATH := /lib/modules/$(shell uname -r)/kernel/net/ipv6

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

install:
	install -D -m 644 $(MODULE_NAME) $(INSTALL_PATH)/$(MODULE_NAME)
	/sbin/depmod -a

uninstall:
	rm -f $(INSTALL_PATH)/$(MODULE_NAME)
	rmdir -p --ignore-fail-on-non-empty $(INSTALL_PATH)
	/sbin/depmod -a
