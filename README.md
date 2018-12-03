# Course Project for Creating a Docker-Image for easy setup of TEACUP 
## Course Code : CO300

### Overview
TEACUP (TCP Experimentation Automation Controlled Using Python) is an automated framework to setup a testbed for 
real time experimentation of TCP. This framework has been proposed by Swinburne University, Australia and has 
been in use since past few years. 
However, setting up this framework is a tedious job and takes away several months. 
At NITK, this framework has been set up successfully. This project aims to use the docker technology to simplify the 
setting of TEACUP in future.

TEACUP is used to automate many aspects of running TCP performance experiments in our specially-constructed physical testbed. TEACUP enables repeatable testing of different TCP algorithms over a range of emulated network path conditions, bottleneck rate limits and bottleneck queuing disciplines.We hope TEACUP proves useful to other researchers who already have (or are interested in setting up) similar network testbeds.

### Instructions for TEACUP testbed setup
1. Make sure you are running Ubuntu.
2. Before running any of the scripts mentioned henceforth;
  - Make the appropriate script executable by using the command 
    <code>chmod +x scriptName.sh</code>
  - Run the script using the command 
    <code>./scriptName.sh</code>
3. Depending on whether your OS type is 32-bit or 64-bit, run install32.sh or install64.sh scripts respectively.
4. Boot with Linux 3.17 kernel by going to "Advanced options for Ubuntu" before system startup after restart. 
5. Make other changes to your kernel by running the installteacup.sh script. 
6. Install Docker by running the installdocker.sh script.
7. Load the Docker image using the command <code>sudo docker load -i teacup.tar</code>
8. Run the container using the command <code>sudo docker run -it teacup</code>
9. Before running teacupstart.sh add path to configuration files in the commands. Also add env.username and env.password at <username> and <password> fields.
10. Run teacupstart.sh to open the teacup files.
11. Run ttprobe.sh inside your teacup-code/tools folder to apple the ttprobe patch to the kernel.
10. Create experiment folder in TEACUP directory containing the teacup-code folder.This will contain the configuration for teacup testbed.
11. Run 
  - teacup-code/example_configs/config-scenario1.py /experiment/config.py
  - cp teacup-1.0/example_configs/run.sh /experiment/
  - cp teacup-1.0/fabfile.py /experiment/
12. Add to config.py file in experiment folder
  - TPCONF_linux_tcp_logger = 'ttprobe'
  - TPCONF_ttprobe_direction = 'io'
  - TPCONF_ttprobe_output_mode = 'o'
13. Add env.user and env.password and also specify the teacup-code path in TPCONF_script_path.
14. Run ./run.sh in experiment folder to generate the required log files.
  
### Instructions for TEACUP testbed setup using Docker containers
1. Make sure you are running Ubuntu.
2. Before running any of the scripts mentioned henceforth;
  - Make the appropriate script executable by using the command 
    <code>chmod +x scriptName.sh</code>
  - Run the script using the command 
    <code>./scriptName.sh</code>
3. Install Docker by running the installdocker.sh script.
4. Load the Docker images for server, client and router using the command <code>sudo docker load -i teacup.tar</code> on the respective machines.
5. Run the containers for server, client and router using the command <code>sudo docker run -it teacup</code> on the respective machines.
6. Navigate to /home/TEACUP/experiment and run TEACUP using command <code>./run.sh</code> on the server's docker container to generate the required log files.

### References
+ http://caia.swin.edu.au/tools/teacup/
+ http://hg.code.sf.net/p/teacup/code
+ https://docs.docker.com/get-started/
+ http://caia.swin.edu.au/reports/150911A/CAIA-TR-150911A.pdf
