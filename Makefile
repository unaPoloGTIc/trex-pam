all: pam-module tests

pam-module: trex-pam.cpp
	g++ -g -std=c++17 -fPIC -c trex-pam.cpp common-raii/common-raii.cpp -Wl,--no-undefined
	g++ -g -std=c++17 -shared -Wl,--no-undefined -o trex-pam.so trex-pam.o common-raii.o -lpam -lqrcodegencpp -lboost_system -lmicrohttpd `gpgme-config --cflags --libs`

tests: pam-tests.cpp pam-module
	g++ -g pam-tests.cpp -o pam-tests -std=c++17 -lgtest -lgmock -lpthread -lpam `gpgme-config --cflags --libs` `curl-config --libs` -lstdc++fs
run-unit-tests: tests
	gpg -d testdec || true #workaround to prime gpg in container TODO: move elsewhere
	LD_PRELOAD=libpam_wrapper.so PAM_WRAPPER=1 PAM_WRAPPER_KEEP_DIR=0 PAM_WRAPPER_DEBUGLEVEL=0 PAM_WRAPPER_USE_SYSLOG=1 PAM_WRAPPER_SERVICE_DIR=./config/ ./pam-tests
dockerize:
	docker build . -f ./containers/Dockerfile.builder -t trexpam-builder
inception-build: dockerize
	docker run --name trexpam-runner --rm -w="/home/docker" trexpam-builder make all
inception-unittest: dockerize
	docker run --name trexpam-runner --rm -w="/home/docker" trexpam-builder make run-unit-tests
clean:
	rm *.so *.o pam-tests
