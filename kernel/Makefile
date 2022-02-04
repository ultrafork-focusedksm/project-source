KO := sus_mod
KERNEL_VERSION := $(shell uname -r)
PWD := $(shell pwd)

ccflags-y := -Wall

obj-m += sus.o
sus-y := sus_main.o
sus-y += focused_ksm.o
sus-y += ultrafork.o
sus-y += hash_tree.o
sus-y += sus_fork.o
sus-y += recursive_task_walker.o
sus-y += cow_counter.o
sus-y += util.o

.PHONY: build install load clean

build:
	$(MAKE) -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) modules

install:
	@cp sus.ko /lib/modules/$(KERNEL_VERSION)
	depmod -a

load:
	modprobe $(KO)

clean:
	$(MAKE) -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) clean
