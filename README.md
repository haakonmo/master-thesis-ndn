master-thesis-ndn
=================

Install 
=======

Install NFD (http://named-data.net/doc/NFD/current/INSTALL.html)

    $ sudo add-apt-repository ppa:named-data/ppa
    $ sudo apt-get update
    $ sudo apt-get install nfd

Install PyNDN2

    $ sudo apt-get install python-setuptools
    $ sudo CFLAGS=-Qunused-arguments easy_install pyndn

Install Git

    $ sudo apt-get install git-core

Clone master thesis repo

    $ cd /opt
    $ git clone https://github.com/haakonmo/master-thesis-ndn.git
    $ cd master-thesis-ndn/

Run
===

Start NFD

    $ nfd-start

Open a new terminal and start the Public Key Generator

    $ python application.py
    $ pkg

Open a new terminal and start the Device

    $ python application.py
    $ data

Open a new terminal and start the Device

    $ python application.py
    $ pull
    $ r

