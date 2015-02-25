#!/bin/sh

sudo add-apt-repository ppa:named-data/ppa
sudo apt-get update
sudo apt-get install nfd

sudo apt-get install python-setuptools
sudo CFLAGS=-Qunused-arguments easy_install pyndn

# install publicKeySyn and its prerequisites
# sudo apt-get install python-nss
sudo apt-get install git-core
cd /opt
git clone https://github.com/haakonmo/master-thesis-ndn.git
cd master-thesis-ndn/
./waf configure
./waf
sudo ./waf install