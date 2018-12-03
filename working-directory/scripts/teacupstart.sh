#!/bin/bash

sudo mkdir /home/($whoami)/Documents/TEACUP
sudo cd /home/($whoami)/Documents/TEACUP
sudo wget http://caia.swin.edu.au/tools/teacup/downloads/teacup-public-1.0.tar.gz
sudo tar -xvzf teacup-public-1.0.tar.gz
sudo mkdir -p experiment
sudo cp teacup-1.0/example_configs/config-scenario1.py /experiment/config.py
sudo cp teacup-1.0/example_configs/run.sh /experiment/
sudo cp teacup-1.0/fabfile.py /experiment/
sudo cd experiment/

#add taking user input functionality
sudo sed -i 's/root/($whoami)' <path/to/config files>
sudo sed -i 's/rootpw/<password>' <path/to/config files>
sudo sed -i '32s/.*/TPCONF_script_path=\/home\/hostname\/Documents\/TEACUP\/teacup-1.0/' <path/to/config files> 
