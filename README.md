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

Install PBC

    $ wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
    $ tar -zxvf pbc-0.5.14.tar.gz
    $ cd pbc-0.5.14
    $ ./configure --prefix=$HOME/.local
    $ make
    $ sudo make install

Install Charm with python 2.7 --> https://github.com/JHUISI/charm/tree/2.7-master
This requires GMP 5.x, PBC (see above) and OPENSSL

    $ git clone https://github.com/JHUISI/charm.git
    $ cd charm
    $ git checkout 2.7-master
    $ ./configure.sh  (include --enable-darwin if running Mac OS X)
    $ sudo make install

Clone master thesis repo

    $ cd /opt
    $ git clone https://github.com/haakonmo/master-thesis-ndn.git

Run
===

Start NFD

    $ nfd-start

Open a new terminal and start the Public Key Generator

    $ cd /path/to/master-thesis-ndn/src/
    $ python application.py
    $ pkg

Open a new terminal and start the Device

    $ python application.py
    $ data

Open a new terminal and start the Device

    $ python application.py
    $ pull
    $ r

