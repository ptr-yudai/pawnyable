obj-m := vuln.o
KBUILD_DIR := /lib/modules/$(KVERSION)/build
CFLAGS_vuln.o := -O1

all:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
