pinger: main.c
	gcc -o pinger -g -lm -lncursesw main.c

install: pinger
	chown root pinger
	chmod u+s pinger
