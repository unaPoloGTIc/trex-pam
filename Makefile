all: pam-module

pam-module:
	g++ -g -std=c++17 -fPIC -c trex-pam.cpp
	g++ -g -std=c++17 -shared -o trex-pam.so trex-pam.o -lpam -lqrcodegencpp -lboost_system -lmicrohttpd `gpgme-config --cflags --libs`

clean:
	rm *.so *.o
