ifeq ($(KERNELRELEASE),)

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

.PHONY: all build clean

# Default target: build both module and user program
all: sneaky_process build

# Compile the user‐space attack program
sneaky_process: sneaky_process.c
	$(CC) -Wall -o sneaky_process sneaky_process.c

# Build the kernel module
build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

# Clean module artifacts and the user program
clean:
	rm -f sneaky_process
	rm -rf *.o *~ core .depend .*.cmd *.order *.symvers *.ko *.mod.c

else

$(info Building sneaky_mod for kernel ${KERNELRELEASE})
obj-m := sneaky_mod.o

endif
