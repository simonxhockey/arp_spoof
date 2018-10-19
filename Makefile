all: arp_spoof

arp_spoof : arp_spoof.o main.o
	g++ -g -o arp_spoof arp_spoof.o main.o -lpcap

arp_spoof.o: arp_spoof.h arp_spoof.cpp
	g++ -g -c -o arp_spoof.o arp_spoof.cpp -lpcap

main.o: arp_spoof.h main.cpp
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arp_spoof
	rm -f *.o


