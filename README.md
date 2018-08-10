Introduction
==============

RYU is a SDN controller to manage openflow switches. RYU is python application which provides API to build custom application to add programability to the network elements. All the openflow switches connect to RYU and receive flows on what actions to perform. 

Note: For this project Open vSwitch[http://openvswitch.org/] has been used as OpenFlow with version 1.4. To build and deploy openflow switch, refer to "OVS_Install.sh".

Installation
-------------

To install the application follow the steps below:
1) Create a network topology and ensure that multiple nodes have 1 interface directly connected to RYU-Controller machine node and has IP assigned on both ends.
2) Install the RYU controller application by running "ryu-installer.sh" from this repo.
3) Run "ryu-manager --verbose" to check the installation
4) Install and configure the openflow switches. Run the switches in "fail-mode" as "secure" to ensure the flows get deleted when Controller is disconnected
5) Connect the switches to RYU Controller by running following command on each node 
 '''shell
 ovs-vsctl set-controller br-int tcp:$SDN_IP_ADDR:6633
 '''
6) An log message for event"EventOFPSwitchFeatures" should show on controller terminal

Running ryu_pseudomac Application
---------------------------------

Remove any running instances of ryu be killing existing process. Then run "ryu-manager ryu_pseudomac.py --verbose" to start the application.
