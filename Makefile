all: pam-module tests

pam-module:
	g++ -g -std=c++11 -static -static-libstdc++ -static-libgcc -Wl,-Bstatic -fext-numeric-literals -fPIC -c trex-pam.cpp common-raii/common-raii.cpp -Wl,--no-undefined
	g++ -g -std=c++11 -static -static-libstdc++ -static-libgcc -Wl,-Bstatic -shared -Wl,--no-undefined -fPIC -fext-numeric-literals -o trex-pam.so trex-pam.o common-raii.o -lpam -lqrcodegencpp -lboost_system -lmicrohttpd -L/usr/lib/x86_64-linux-gnu -Llibgpgme.a -Llibassuan.a -Llibgpg-error.a

tests: pam-module
	g++ -g pam-tests.cpp -o pam-tests -std=c++17 -lgtest -lgmock -lpthread -lpam `gpgme-config --cflags --libs` `curl-config --libs`
run-unit-tests: tests
	LD_PRELOAD=libpam_wrapper.so PAM_WRAPPER=1 PAM_WRAPPER_KEEP_DIR=1 PAM_WRAPPER_DEBUGLEVEL=3 PAM_WRAPPER_USE_SYSLOG=1 PAM_WRAPPER_SERVICE_DIR=./config/ ./pam-tests
clean:
	rm *.so *.o pam-tests
