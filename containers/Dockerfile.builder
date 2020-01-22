FROM debian:bullseye
#TODO: consider debian:latest

RUN apt-get update && apt-get install -y --force-yes --fix-missing \
    libgpgme11 libstdc++6 openssh-server sudo libqrcodegen1 libqrcodegencpp1 \
    libpam0g libgpgmepp6 libmicrohttpd12 libboost-system1.67.0 libassuan0 libgpg-error0 \
    libcurl4-g* \
    make g++ libgpgme-dev libmicrohttpd-dev libpam0g-dev libqrcodegencpp-dev \
    libboost-system-dev libgmock-dev

RUN mkdir /var/run/sshd
RUN echo 'root:1234' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

#ADD sshd /etc/pam.d/sshd

RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

RUN useradd docker \
        && passwd -d docker \
        && mkdir /home/docker \
        && chown docker:docker /home/docker \
        && addgroup docker staff \
        && addgroup docker sudo \
        && true
RUN echo 'docker:1234' | chpasswd
RUN echo 'docker            ALL = (ALL) NOPASSWD: ALL' >> /etc/sudoers

#ADD sshd_config /etc/ssh/sshd_config

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

EXPOSE 2222

USER docker

ADD ./ /home/docker

CMD ["sudo", "/usr/sbin/sshd", "-D", "-p2222"]
