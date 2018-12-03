# Experiment with two tcp flows going through two different routers 
#
# $Id$

import sys
import datetime
from fabric.api import env


#
# Fabric config
#

# User and password
env.user = 'root'
env.password = 'rootpw'

# Set shell used to execute commands
env.shell = '/bin/sh -c'

#
# Testbed config
#

# Path to teacup scripts
TPCONF_script_path = '/home/teacup/teacup-0.9'
# DO NOT remove the following line
sys.path.append(TPCONF_script_path)

# Set debugging level (0 = no debugging info output) 
TPCONF_debug_level = 1

# Host lists
TPCONF_router = ['newtcprt2', 'newtcprt3' ]
TPCONF_hosts = [ 'newtcp30', 'newtcp31', 'newtcp32', 'newtcp33' ]

# Map external IPs to internal IPs
TPCONF_host_internal_ip = {
    'newtcprt2': ['172.16.12.1', '172.16.13.1'],
    'newtcprt3': ['172.16.10.1', '172.16.11.1'],
    'newtcp30':  ['172.16.10.70'],
    'newtcp31':  ['172.16.11.71'],
    'newtcp32':  ['172.16.12.72'],
    'newtcp33':  ['172.16.13.73'],
}

TPCONF_config_topology = '1'

# Host name or IP of switch hosts are connected to
#TPCONF_topology_switch = 'switch1' # V1 testbed
TPCONF_topology_switch = 'switch2' # V2 testbed

# Prefix for switch port names hosts are connected to
#TPCONF_topology_switch_port_prefix = 'ethernet g' # V1 testbed
TPCONF_topology_switch_port_prefix = 'Gi1/0/' # V2 testbed

# Offset between number in host name and switch port number
#TPCONF_topology_switch_port_offset = 14 # V1 testbed 
TPCONF_topology_switch_port_offset = 5 # V2 testbed

TPCONF_check_connectivity = '1'

# Time offset measurement options
# Enable broadcast ping on external/control interfaces
TPCONF_bc_ping_enable = '1'

# Specify rate of pings in packets/second
TPCONF_bc_ping_rate = 1

# Specify multicast address to use (must be broadcast or multicast address)
# If this is not specified, byt deafult the ping will be send to the subnet
# broadcast address.
TPCONF_bc_ping_address = '224.0.1.199'

#
# Reboot configuration
#

# TFTP server to use
TPCONF_tftpserver = '10.1.1.11:8080'

# Path to tftp server handling the pxe boot
# Setting this to an empty string '' means no PXE booting, and TPCONF_host_os
# and TPCONF_force_reboot are simply ignored
TPCONF_tftpboot_dir = '/tftpboot'

# Operating system config, machines that are not explicitely listed are
# left as they are (OS can be 'Linux', 'FreeBSD', 'CYGWIN' or 'Darwin')
TPCONF_host_os = {
    'newtcprt2': 'Linux',
    'newtcprt3': 'Linux',
    'newtcp30': 'Linux',
    'newtcp31': 'Linux',
    'newtcp32': 'Linux',
    'newtcp33': 'Linux',
}

# Specify the Linux kernel to use, only used for machines running Linux
# (basically the full name without the vmlinuz-)
# Set variable to 'running' to choose currently running kernel
#TPCONF_linux_kern_router = '3.10.18-vanilla-10000hz'
TPCONF_linux_kern_router = '3.17.4-vanilla-10000hz'
#TPCONF_linux_kern_hosts = '3.7.10-1.16-desktop-web10g'
TPCONF_linux_kern_hosts = '3.17.4-vanilla-web10g'

# Force reboot
# If set to '1' will force a reboot of all hosts
# If set to '0' only hosts where OS is not the desired OS will be rebooted
TPCONF_force_reboot = '0'

# Time to wait for reboot in seconds (integer)
# if host is not back up within this time we either power cycle
# (if TPCONF_power_cycle is '1') or we give up
# Minimum timeout is 60 seconds
TPCONF_boot_timeout = 130

# If host does not come up within timeout force power cycle
# If set to '1' force power cycle if host not up within timeout
# If set to '0' never force power cycle
TPCONF_do_power_cycle = '0'


#
# Experiment settings
#

# Maximum allowed time difference between machines in seconds
# otherwise experiment will abort cause synchronisation problems
TPCONF_max_time_diff = 2

# Experiment name prefix used if not set on the command line
# The command line setting will overrule this config setting
now = datetime.datetime.today()
# old default test ID prefix (version < 1.0)
#TPCONF_test_id = now.strftime("%Y%m%d-%H%M%S") + '_experiment'
# new default test ID prefix
TPCONF_test_id = 'exp_' + now.strftime("%Y%m%d-%H%M%S")

# Directory to store log files on remote host
TPCONF_remote_dir = '/tmp/'

#
# List of router queues/pipes
#

# Each entry is a tuple. The first value is the queue number and the second value
# is a comma separated list of parameters (see routersetup.py:init_pipe()).
# Queue numbers must be unique.

# Note that variable parameters must be either constants or or variable names
# defined by the experimenter. Variables are evaluated during runtime. Variable
# names must start with a 'V_'. Parameter names can only contain numbes, letter
# (upper and lower case), underscores (_), and hypen/minus (-).

# All variables must be defined in TPCONF_variable_list (see below).

# Note parameters must be configured appropriately for the router OS, e.g. there
# is no CoDel on FreeBSD; otherwise the experiment will abort witn an error.

newtcprt2_queues = [
    # Set same delay for every host
    ('1', " source='172.16.12.0/24', dest='172.16.13.0/24', delay=V_delay, "
     " loss=V_loss, rate=V_up_rate, queue_disc=V_aqm, queue_size=V_bsize "),
    ('2', " source='172.16.13.0/24', dest='172.16.12.0/24', delay=V_delay, "
     " loss=V_loss, rate=V_down_rate, queue_disc=V_aqm, queue_size=V_bsize "),
]

newtcprt3_queues = [
    # Set same delay for every host
    ('1', " source='172.16.10.0/24', dest='172.16.11.0/24', delay=V_delay2, "
     " loss=V_loss, rate=V_up_rate, queue_disc=V_aqm2, queue_size=V_bsize "),
    ('2', " source='172.16.11.0/24', dest='172.16.10.0/24', delay=V_delay2, "
     " loss=V_loss, rate=V_down_rate, queue_disc=V_aqm2, queue_size=V_bsize "),
]


TPCONF_router_queues = {}
TPCONF_router_queues['newtcprt2'] = newtcprt2_queues
TPCONF_router_queues['newtcprt3'] = newtcprt3_queues

#
# List of traffic generators
#

# Each entry is a 3-tuple. the first value of the tuple must be a float and is the
# time relative to the start of the experiment when tasks are excuted. If two tasks
# have the same start time their start order is arbitrary. The second entry of the
# tuple is the task number and  must be a unique integer (used as ID for the process).
# The last value of the tuple is a comma separated list of parameters (see the tasks
# defined in trafficgens.py); the first parameter of this list must be the
# task name.

# Client and server can be specified using the external/control IP addresses or host
# names. Then the actual interface used is the _first_ internal address (according to
# TPCONF_host_internal_ip). Alternativly, client and server can be specified as
# internal addresses, which allows to use any internal interfaces configured.

traffic_iperf = [
    # Specifying external addresses traffic will be created using the _first_
    # internal addresses (according to TPCONF_host_internal_ip)
    ('0.0', '1', " start_iperf, client='newtcp30', server='newtcp31', port=5000, "
     " duration=V_duration, buf_size=1228800 "),
    ('0.0', '2', " start_iperf, client='newtcp32', server='newtcp33', port=5001, "
     " duration=V_duration, buf_size=1228800 "),
]

# THIS is the traffic generator setup we will use
TPCONF_traffic_gens = traffic_iperf

#
# Traffic parameters 
#

# Duration in seconds of traffic
TPCONF_duration = 60

# Number of runs for each setting
TPCONF_runs = 1

# TCP congestion control algorithm used
# Possible algos are: default, host<N>, newreno, cubic, cdg, hd, htcp, compound, vegas
# Note that the algo support is OS specific, so must ensure the right OS is booted
# Windows: newreno (default), compound
# FreeBSD: newreno (default), cubic, hd, htcp, cdg, vegas
# Linux: newreno, cubic (default), htcp, vegas
# Mac: newreno
# If you specify 'default' the default algorithm depending on the OS will be used
# If you specify 'host<N>' where <N> is an integer starting from 0 to then the
# algorithm will be the N-th algorithm specified for the host in TPCONF_host_TCP_algos 
# (in case <N> is larger then the number of algorithms specified, it is set to 0
TPCONF_TCP_algos = ['cubic', ]

# Specify TCP congestion control algorithms used on each host
TPCONF_host_TCP_algos = {
    'newtcp30': ['default', 'newreno', ],
    'newtcp31': ['default', 'newreno', ],
    'newtcp32': ['default', 'newreno', ],
    'newtcp33': ['default', 'newreno', ],
}

# Specify TCP parameters for each host and each TCP congestion control algorithm
# Each parameter is of the form <sysctl name> = <value> where <value> can be a constant
# or a V_ variable
TPCONF_host_TCP_algo_params = {
}

# Specify arbitray commands that are executed on a host at the end of the host 
# intialisation (after general host setup, ecn and tcp setup). The commands are
# executed in the shell as written after any V_ variables have been replaced.
# LIMITATION: only one V_ variable per command
TPCONF_host_init_custom_cmds = {
}

# Emulated delays in ms
TPCONF_delays = [25]
TPCONF_delays2 = [50]

# Emulated loss rates
TPCONF_loss_rates = [0]

# Emulated bandwidths (downstream, upstream)
TPCONF_bandwidths = [
    ('10mbit', '10mbit'),
]

# AQM
# Linux: fifo (mapped to pfifo), pfifo, bfifo, fq_codel, codel, pie, red, ...
#        (see tc man page for full list)
# FreeBSD: fifo, red
TPCONF_aqms = ['pfifo', ]
TPCONF_aqms2 = ['fq_codel', ]

# Buffer size
# If router is Linux this is mostly in packets/slots, but it depends on AQM
# (e.g. for bfifo it's bytes)
# If router is FreeBSD this would be in slots by default, but we can specify byte sizes
# (e.g. we can specify 4Kbytes)
TPCONF_buffer_sizes = [100]

#
# List of all parameters that can be varied and default values
#

# The key of each item is the identifier that can be used in TPCONF_vary_parameters
# (see below).
# The value of each item is a 4-tuple. First, a list of variable names.
# Second, a list of short names uses for the file names.
# For each parameter varied a string '_<short_name>_<value>' is appended to the log
# file names (appended to chosen prefix). Note, short names should only be letters
# from a-z or A-Z. Do not use underscores or hyphens!
# Third, the list of parameters values. If there is more than one variable this must
# be a list of tuples, each tuple having the same number of items as teh number of
# variables. Fourth, an optional dictionary with additional variables, where the keys
# are the variable names and the values are the variable values.

TPCONF_parameter_list = {
#   Vary name		V_ variable	  file name	values			extra vars
    'delays' 	    :  (['V_delay'], 	  ['del'], 	TPCONF_delays, 		 {}),
    'delays2' 	    :  (['V_delay2'], 	  ['del2'], 	TPCONF_delays2, 	 {}),
    'loss'  	    :  (['V_loss'], 	  ['loss'], 	TPCONF_loss_rates, 	 {}),
    'tcpalgos' 	    :  (['V_tcp_cc_algo'],['tcp'], 	TPCONF_TCP_algos, 	 {}),
    'aqms'	    :  (['V_aqm'], 	  ['aqm'], 	TPCONF_aqms, 		 {}),
    'aqms2'	    :  (['V_aqm2'], 	  ['aqm2'], 	TPCONF_aqms2, 		 {}),
    'bsizes'	    :  (['V_bsize'], 	  ['bs'], 	TPCONF_buffer_sizes, 	 {}),
    'runs'	    :  (['V_runs'],       ['run'], 	range(TPCONF_runs), 	 {}),
    'bandwidths'    :  (['V_down_rate', 'V_up_rate'], ['down', 'up'], TPCONF_bandwidths, {}),
}

# Default setting for variables (used for variables if not varied)

# The key of each item is the parameter  name. The value of each item is the default
# parameter value used if the variable is not varied.

TPCONF_variable_defaults = {
#   V_ variable			value
    'V_duration'  	:	TPCONF_duration,
    'V_delay'  		:	TPCONF_delays[0],
    'V_delay2' 		:	TPCONF_delays2[0],
    'V_loss'   		:	TPCONF_loss_rates[0],
    'V_tcp_cc_algo' 	:	TPCONF_TCP_algos[0],
    'V_down_rate'   	:	TPCONF_bandwidths[0][0],
    'V_up_rate'	    	:	TPCONF_bandwidths[0][1],
    'V_aqm'	    	:	TPCONF_aqms[0],
    'V_aqm2'	    	:	TPCONF_aqms2[0],
    'V_bsize'	    	:	TPCONF_buffer_sizes[0],
}

# Specify the parameters we vary through all values, all others will be fixed
# according to TPCONF_variable_defaults
TPCONF_vary_parameters = ['delays', 'delays2', 'bandwidths', 'aqms', 'aqms2', 'runs',]
