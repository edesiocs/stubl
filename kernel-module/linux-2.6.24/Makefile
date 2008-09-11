obj-m    := stubl.o
KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

modules clean:
	$(MAKE) -C $(KDIR) M=$(PWD) $@

install modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	-/sbin/depmod -a || :;

INSTALL_PATH := /lib/modules/$(shell uname -r)/extra
uninstall:
	rm -f $(INSTALL_PATH)/stubl.ko
	rmdir -p --ignore-fail-on-non-empty $(INSTALL_PATH)
	-/sbin/depmod -a
