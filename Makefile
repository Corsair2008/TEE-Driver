obj-m=corsair.o
corsair-objs=tee_core.o

KDIR?=/lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=`pwd` modules

clean:
	make -C $(KDIR) M=`pwd` modules clean
