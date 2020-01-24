FROM debian:bullseye AS setuptests
#TODO: consider debian:latest

RUN apt-get update && apt-get install -y --force-yes --fix-missing \
    libgpgme11 libstdc++6 openssh-server sudo libqrcodegen1 libqrcodegencpp1 \
    libpam0g libgpgmepp6 libmicrohttpd12 libboost-system1.67.0 libassuan0 libgpg-error0 \
    libcurl4-g* \
    make g++ libgpgme-dev libmicrohttpd-dev libpam0g-dev libqrcodegencpp-dev \
    libboost-system-dev libgmock-dev libpam-wrapper

RUN mkdir /var/run/sshd
RUN echo 'root:1234' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

ADD ./containers/sshd /etc/pam.d/sshd

RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

RUN useradd docker \
        && passwd -d docker \
        && mkdir /home/docker \
        && chown -R docker:docker /home/docker \
        && addgroup docker staff \
        && addgroup docker sudo \
        && true
RUN echo 'docker:1234' | chpasswd
RUN echo 'docker            ALL = (ALL) NOPASSWD: ALL' >> /etc/sudoers

ADD ./containers/sshd_config /etc/ssh/sshd_config

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

#workaround for sudo issue (sudo: setrlimit(RLIMIT_CORE): Operation not permitted)
RUN echo Set disable_coredump false > /etc/sudo.conf
RUN cat /etc/sudo.conf

EXPOSE 2222

USER docker

COPY --chown=docker:docker . /home/docker
COPY --chown=docker:docker containers/.auth_gpg /home/docker/.auth_gpg
COPY --chown=docker:docker containers/mmotd-module /home/docker/config/mmotd-module
COPY --chown=docker:docker containers/keyparams /home/docker/keyparams

WORKDIR /home/docker
RUN openssl genrsa -out server.key 1024
RUN openssl req -days 3650 -out server.pem -new -x509 -key server.key \
    -subj "/C=NL/ST=Zyesyes/L=nono/O=where/OU=devedev/CN=none.com"
RUN gpg --gen-key  --trust-model always --passphrase='' --no-tty --batch keyparams

RUN echo test | gpg -ae -r vendortest@mmodt.com > testdec
RUN gpg -d testdec
RUN gpg --list-secret-keys

ONBUILD RUN make run-unit-tests

CMD ["sudo", "/usr/sbin/sshd", "-D", "-p2222"]

FROM setuptests AS demoimage

#TODO: remove test keys
#RUN gpg --no-tty --yes --delete-secret-and-public-keys vendortest@mmodt.com
COPY --chown=docker:docker containers/vendor.pub /home/docker/vendor.pub
RUN gpg --import --trust-model always < /home/docker/vendor.pub
RUN rm /home/docker/vendor.pub
RUN sed -i 's/vendortest@mmodt.com/vendor@mmodt.com/' /home/docker/.auth_gpg