KO := sus_mod
KERNEL_VERSION := $(shell uname -r)
PWD := $(shell pwd)

obj-m += sus.o
sus-y := sus_main.o
sus-y += focused_ksm.o
sus-y += ultrafork.o

.PHONY: build install load clean

build:
	$(MAKE) -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) modules

install:
	@cp $(KO).ko /lib/modules/$(KERNEL_VERSION)
	depmod -a

load:
	modprobe $(KO)

clean:
	$(MAKE) -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) clean
