ctcontainername = trexpam-ct
testimagename = trexpam-demo-builder
demoimagename = trexsec/pam-demo:latest
containermake = docker run --name trexpam-runner --rm -w="/home/docker" $(testimagename) make

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
	$(containermake) all
inception-unittest: dockerize-tests
	$(containermake) run-unit-tests
dockerize-demoimage:
	#unittests run automatically via ONBUILD directive at dockerfile
	docker build . -f ./containers/Dockerfile.builder -t $(testimagename)
ct-build: ct.cpp
	g++ -g -std=c++17 ct.cpp -lssh -o ct `curl-config --libs`
inception-componenttest: ct-build dockerize-demoimage
	docker stop $(ctcontainername) || true
	docker run --name $(ctcontainername) --rm -w="/home/docker" -td --network host $(testimagename)
	sleep 3
	ssh-keygen -f "$$HOME/.ssh/known_hosts" -R "[localhost]:2222" || true
	./ct
	docker stop $(ctcontainername) || true
push: inception-componenttest
	docker tag $(testimagename) $(demoimagename)
	#workaround if pushing via SSH without X
	#dbus-run-session bash
	#gnome-keyring-daemon -r
	docker push $(demoimagename)
clean:
	rm *.so *.o pam-tests
