FROM ubuntu:14.04
MAINTAINER pramod bs (prmdbs3@gmail.com)
RUN echo Sit back and relax while this docker image takes care of TEACUP setup !
RUN apt-get update && apt-get install -y python2.7
RUN apt-get install -y python-pip
RUN pip install --upgrade pip
RUN pip install fabric
RUN apt-get update
RUN apt-get install -y wget
RUN wget http://caia.swin.edu.au/tools/spp/downloads/spp-0.3.6.tar.gz
RUN tar -xvzf spp-0.3.6.tar.gz
RUN apt-get install -y libpcap0.8-dev
RUN cd spp-0.3.6 && make
RUN wget http://caia.swin.edu.au/tools/teacup/downloads/teacup-public-1.0.tar.gz
RUN tar -xvzf teacup-public-1.0.tar.gz && ls
RUN cd teacup-1.0/tools/ && tar -xvzf iperf-2.0.5-mod.tar.gz && cd iperf-2.0.5-mod && ./configure && make && make install
RUN cd teacup-1.0/tools/ && tar -xvzf nttcp-1.47-mod.tar.gz && cd nttcp-1.47-mod/ && make
RUN apt-get install -y r-base
RUN apt-get install -y pdfjam
RUN pip install pexpect 3-1
