all: uld.a udpecho threcho uldmap uldcap

CFL= -g

uld.a: */*.[ch]
	rm -f uld.a *.o
	cc -Wall -c ${CFL} uld/*.c vfio/*.c uenic/*.c ixvf/*.c igbvf/*.c
	ar r uld.a *.o

threcho: tools/threcho.c uld.a
	cc -o threcho ${CFL} tools/threcho.c uld.a -lrt -lnl

udpecho: tools/udpecho.c uld.a
	cc -o udpecho ${CFL} tools/udpecho.c uld.a -lrt -lnl

uldcap: tools/uldcap.c uld.a
	cc -o uldcap ${CFL} tools/uldcap.c uld.a -lrt -lpcap -lnl

uldmap: tools/uldmap.c uld.a
	cc -o uldmap ${CFL} tools/uldmap.c uld.a -lrt -lnl

clean:
	rm -f uld.a *.o

dist:
	tar cfz - Makefile COPYING README */*.[ch] > uld.tgz
