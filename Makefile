all: pam-module tests

pam-module: trex-pam.cpp
	g++ -g -std=c++17 -fPIC -c trex-pam.cpp common-raii/common-raii.cpp -Wl,--no-undefined
	g++ -g -std=c++17 -shared -Wl,--no-undefined -o trex-pam.so trex-pam.o common-raii.o -lpam -lqrcodegencpp -lboost_system -lmicrohttpd `gpgme-config --cflags --libs`

tests: pam-tests.cpp pam-module
	g++ -g pam-tests.cpp -o pam-tests -std=c++17 -lgtest -lgmock -lpthread -lpam `gpgme-config --cflags --libs` `curl-config --libs` -lstdc++fs
run-unit-tests: tests
	gpg -d testdec || true #workaround to prime gpg in container TODO: move elsewhere
	LD_PRELOAD=libpam_wrapper.so PAM_WRAPPER=1 PAM_WRAPPER_KEEP_DIR=0 PAM_WRAPPER_DEBUGLEVEL=0 PAM_WRAPPER_USE_SYSLOG=1 PAM_WRAPPER_SERVICE_DIR=./config/ ./pam-tests
dockerize-tests:
	docker build . -f ./containers/Dockerfile.builder -t trexpam-test-builder --target setuptests
inception-build: dockerize-tests
	docker run --name trexpam-runner --rm -w="/home/docker" trexpam-test-builder make all
inception-unittest: dockerize-tests
	docker run --name trexpam-runner --rm -w="/home/docker" trexpam-test-builder make run-unit-tests
dockerize-demoimage:
	docker build . -f ./containers/Dockerfile.builder -t trexpam-demo-builder
inception-componenttest: dockerize-demoimage
	docker run --name trexpam-ct --rm -w="/home/docker" -td --network host trexpam-demo-builder
	#TODO: query demo server for response (with a script?)
	ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[localhost]:2222"
	ssh -o StrictHostKeyChecking=no docker@localhost -p2222 /bin/true
	docker stop trexpam-ct
push: inception-componenttest
	#docker tag
	#docker push
clean:
	rm *.so *.o pam-tests
