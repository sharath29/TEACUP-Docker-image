# Script to install Web10g and run TEACUP Docker container

#!/bin/bash
sudo docker load -i teacupimage.tar.gz
# save the image with the name "teacupcontainer"
# save command --> docker save -o teacupimage.tar.gz teacupcontainer
sudo docker run -it teacupcontainer
