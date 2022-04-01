obj-m := vuln.o
#KBUILD_DIR := /lib/modules/$(KVERSION)/build
KBUILD_DIR := /home/ptr/armoury/buildroot/output/build/linux-5.16.14
CFLAGS_vuln.o := -O1

all:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
