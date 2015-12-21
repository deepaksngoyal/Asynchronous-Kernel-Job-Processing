obj-m += sys_submitjob.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

sys_submitjob-y := submitjob.o sj_crypt.o sj_compress.o

all: jobctl submitjob

jobctl: jobctl.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi jobctl.c -o jobctl -l ssl

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f jobctl
