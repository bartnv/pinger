pinger: main.c
	gcc -o pinger -g -lncurses main.c

install: pinger
	chown root pinger
	chmod u+s pinger
