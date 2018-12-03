#!/bin/bash

sudo apt-get install openssh-server
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.factory-defaults
sudo chmod a-w /etc/ssh/sshd_config.factory-defaults
sudo sed -i 's/quiet splash/quiet' /etc/default/grub
sudo update-grub
sudo sed -i 's/APT::Periodic::Update-Package-Lists “1”/APT::Periodic::Update-Package-Lists “0”' /etc/apt/apt.conf.d/10periodic

# client side

sudo apt-get install ntp
sudo gedit /etc/ntp.conf :

# set server ip address 
# server 192.168.50.1:

sudo service ntp restart
# Turn off firewall :
sudo ufw disable