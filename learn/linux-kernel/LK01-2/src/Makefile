obj-m := vuln.o
KBUILD_DIR := /lib/modules/$(KVERSION)/build
CFLAGS_vuln.o := -O0

all:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
