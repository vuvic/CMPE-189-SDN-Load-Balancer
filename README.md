# CMPE-189-SDN-Load-Balancer
## Installation & Setup
In a virtual machine with Mininet and Ryu installed, clone this repository and ```cd``` into its directory. To start the load balancer application, run the following command in the terminal: ```ryu-manager rrlb.py &```.

Create the network topology: ```mn --topo single,5 --mac --controller=remote``` and configure the hosts:
```
h1 ifconfig h1-eth0 10.0.0.1/24
h2 ifconfig h2-eth0 10.0.0.2/24
h3 ifconfig h3-eth0 10.0.0.3/24
h4 ifconfig h4-eth0 10.0.0.4/24
h5 ifconfig h5-eth0 10.0.0.10/24
```
Feel free to ping the VIP and observe the round-robin load balancing in action:
```
h4 ping 10.0.0.100       # Ping the VIP with host 4 once per second until stopped with Ctrl + C
h5 ping -c 1 10.0.0.100  # Ping the VIP once with host 5 
```
