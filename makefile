UNAME := $(shell uname)

pinger: main.c
	gcc -o pinger -g -lm -lncursesw main.c

install: pinger
ifeq ($(UNAME), Linux)
	setcap cap_net_raw=ep pinger
else
	chown root pinger
	chmod u+s pinger
endif
