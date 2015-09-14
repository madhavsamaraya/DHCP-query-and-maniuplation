# DHCP-query-and-maniuplation'



Project Report: 

-	To implement a test case scenario for DHCP manipulation and query for the server. This should be done at runtime without the need of restarting the DHCP server:
o	Create/Delete scope (range)
o	Add/Delete Reservation with IP address and MAC address
o	After reservation lookup the IP address with MAC

o	Further Implementation needed:
•	To allow for DHCP to suggest what IP address to give based off the MAC address that the client is using 
•	Furthermore, this can allow what IP range to generate or choose IP range prewritten on dhcp configuration file in order to decide what IP address to handout  

-	This needs to be done on two different virtualized operating systems:
o	Redhat Enterprise Linux Server release 6.5 (Santiago)
o	Microsoft Windows Server 2012

-	Redhat Linux:
o	Using Omapi and automating with Python 2.6.6
o	Omapi: an API for manipulating remote object via runtime

-	Windows Server 2012:
o	Using Powershell 3 to utilize the Cmdlets to control DHCP


















What has been done:

	In Linux:

-	A static host can be created directly into dhcpd.leases file
o	This will have IP and MAC allocation
o	Can lookup IP from MAC
•	But can’t look up MAC from IP (Omapi restrictions)

-	The scope (range) could not be modified by omapi. 
o	Ranges need to be hardcoded into dhcpd.conf file
o	There is no possible way for dhcpd.conf file to be manipulated 
•	Confirmed with ISC DHCP company in Redwood City, CA
•	Jason Lasky: jason@isc.org

-	What more can be done: 
o	Maybe create groups and hardcode into dhcpd.conf file
•	Then ask omapi to add group
•	Add this code inside pypureomapi.py 
o	found on their website: https://github.com/CygnusNetworks/pypureomapi

o	Implement dhcp discover packet to be sent and receive dhcp offer to suggest and print IP

o	Dynamically choose range or create/delete range for appropriate IP address to be given to mac



Create group:

A group needs at least one statement. See UseCaseSupersedeHostname for example statements.
def add_group(omapi, groupname, statements):
    """
    @type omapi: Omapi
    @type groupname: bytes
    @type statements: str
    """
    msg = OmapiMessage.open("group")
    msg.message.append(("create", struct.pack("!I", 1)))
    msg.obj.append(("name", groupname))
    msg.obj.append(("statements", statements))
    response = self.query_server(msg)
    if response.opcode != OMAPI_OP_UPDATE:
        raise OmapiError("add group failed")

And with that, to attach a new host to a group:
def add_host_with_group(omapi, ip, mac, groupname):
    msg = OmapiMessage.open("host")
    msg.message.append(("create", struct.pack("!I", 1)))
    msg.message.append(("exclusive", struct.pack("!I", 1)))
    msg.obj.append(("hardware-address", pack_mac(mac)))
    msg.obj.append(("hardware-type", struct.pack("!I", 1)))
    msg.obj.append(("ip-address", pack_ip(ip)))
    msg.obj.append(("group", groupname))
    response = omapi.query_server(msg)
    if response.opcode != OMAPI_OP_UPDATE:
        raise OmapiError("add failed")

		
		
Suspersede Hostname example

def add_host_supersede_name(omapi, ip, mac, name):
    """Add a host with a fixed-address and override its hostname with the given name.
    @type omapi: Omapi
    @type ip: str
    @type mac: str
    @type name: str
    @raises ValueError:
    @raises OmapiError:
    @raises socket.error:
    """
    msg = OmapiMessage.open("host")
    msg.message.append(("create", struct.pack("!I", 1)))
    msg.message.append(("exclusive", struct.pack("!I", 1)))
    msg.obj.append(("hardware-address", pack_mac(mac)))
    msg.obj.append(("hardware-type", struct.pack("!I", 1)))
    msg.obj.append(("ip-address", pack_ip(ip)))
    msg.obj.append(("name", name))
    msg.obj.append(("statement", "supersede host-name %s;" % name))
    response = omapi.query_server(msg)
    if response.opcode != OMAPI_OP_UPDATE:
        raise OmapiError("add failed")



-	This can be done after a dhcp discover packet is sent and receives dhcp offer to suggest and print IP
o	Written in python
o	http://code.activestate.com/recipes/577649-dhcp-query/

import socket
import struct
from uuid import getnode as get_mac
from random import randint

def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb

class DHCPDiscover:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t) 

    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transactionID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + macb
        packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet

class DHCPOffer:
    def __init__(self, data, transID):
        self.data = data
        self.transID = transID
        self.offerIP = ''
        self.nextServerIP = ''
        self.DHCPServerIdentifier = ''
        self.leaseTime = ''
        self.router = ''
        self.subnetMask = ''
        self.DNS = []
        self.unpack()
    
    def unpack(self):
        if self.data[4:8] == self.transID :
            self.offerIP = '.'.join(map(lambda x:str(x), data[16:20]))
            self.nextServerIP = '.'.join(map(lambda x:str(x), data[20:24]))  #c'est une option
            self.DHCPServerIdentifier = '.'.join(map(lambda x:str(x), data[245:249]))
            self.leaseTime = str(struct.unpack('!L', data[251:255])[0])
            self.router = '.'.join(map(lambda x:str(x), data[257:261]))
            self.subnetMask = '.'.join(map(lambda x:str(x), data[263:267]))
            dnsNB = int(data[268]/4)
            for i in range(0, 4 * dnsNB, 4):
                self.DNS.append('.'.join(map(lambda x:str(x), data[269 + i :269 + i + 4])))
                
    def printOffer(self):
        key = ['DHCP Server', 'Offered IP address', 'subnet mask', 'lease time (s)' , 'default gateway']
        val = [self.DHCPServerIdentifier, self.offerIP, self.subnetMask, self.leaseTime, self.router]
        for i in range(4):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))
        
        print('{0:20s}'.format('DNS Servers') + ' : ', end='')
        if self.DNS:
            print('{0:15s}'.format(self.DNS[0]))
        if len(self.DNS) > 1:
            for i in range(1, len(self.DNS)): 
                print('{0:22s} {1:15s}'.format(' ', self.DNS[i])) 

if __name__ == '__main__':
    #defining the socket
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
    
    try:
        dhcps.bind(('', 68))    #we want to send from port 68
    except Exception as e:
        print('port 68 in use...')
        dhcps.close()
        input('press any key to quit...')
        exit()
 
    #buiding and sending the DHCPDiscover packet
    discoverPacket = DHCPDiscover()
    dhcps.sendto(discoverPacket.buildPacket(), ('<broadcast>', 67))
    
    print('DHCP Discover sent waiting for reply...\n')
    
    #receiving DHCPOffer packet  
    dhcps.settimeout(3)
    try:
        while True:
            data = dhcps.recv(1024)
            offer = DHCPOffer(data, discoverPacket.transactionID)
            if offer.offerIP:
                offer.printOffer()
                break
    except socket.timeout as e:
        print(e)
    
    dhcps.close()   #we close the socket
    
    input('press any key to quit...')
    exit()
	

In Windows:
		
-	The scope (ranges) can be added/deleted dynamically
o	The scope information can be looked up
-	The IP reservation can be made/deleted
o	The IP reservation can be looked up


-	What more can be done:
o	Implement dhcp discover packet to be sent and receive dhcp offer to suggest and print IP
o	See example code above for Linux 
•	http://code.activestate.com/recipes/577649-dhcp-query/
•	
o	Dynamically choose range or create/delete range for appropriate IP address to be given to mac













Documentation:


Madhav Project Folder:

Documentation:
	
Look at documentation folder provided:
-	DHCP with Omapi information, latest one for latest unstable version of DHCP, most of the information is valid for our use
-	Redhat Linux 6 Documentation

Pypureomapi: 
-	https://github.com/CygnusNetworks/pypureomapi/blob/master/pypureomapi.py

Future Updates (Assigning or suggesting IP address or pool based on MAC address)


-	http://code.activestate.com/recipes/577649-dhcp-query/
o	Python script that send a Dhcp discover packet and receives the Dhcp offer that contains a suggested IP address 
o	This has been tried by others on windows
o	Hypothetically work for linux

-	http://stackoverflow.com/questions/25124500/sending-dhcp-discover-using-python-scapy
o	Sending DHCP discover using python Scapy

-	http://www.deepshiftlabs.com/dev_blog/?p=933&lang=en-us
o	Assigning dynamic IP to VM without DHCP

	
Files:

-	dhcp.py
o	this is the python file for linux
-	pypureomapi.py
o	this is the file for python code to work with ompai




Controlling DHCP in Linux:

-	Have a stable and current level of Redhat Linux. 
o	The procedure was implemented in RHEL v6.6.
-	Install ISC DHCP
-	Download pypureomapi.py
-	Download dhcp.py
-	Command Examples





Installing DHCP package that came with Redhat Linux:

Configuring DHCP server

 

Editing the Configuration File

	Check if there is a dhcpd.conf file. This should be in this location:
		/etc/dhcpd/dhcpd.conf

	If there is none, create a file in that location and paste this:

#This is so that omapi can connect to DHCP
 
key jpm_key {
    algorithm HMAC-MD5;
    secret 8keHkH9a4orx/k9AZWiEhQ==;
#The Secret is made from generating a dnssec-key

};

omapi-port 7911;
omapi-key jpm_key;

default-lease-time 600;
max-lease-time 7200;


# This is a very basic subnet declaration.

subnet 61.83.31.0 netmask 255.255.255.0 {
#  range 61.83.31.2 61.83.31.252;
}

Initialize the Lease Database

	Check if there is a dhcpd.leases file. This should be in this location:
		/var/lib/dhcpd/dhcpd.leases

	If there is none, create an empty file in that location


Edit the network /etc/sysconfig/network-scripts/ifcfg-eth0 as below in order to enable dhcp client:

DEVICE="eth0"
BOOTPROTO="dhcp"
IPV6INIT="yes"
ONBOOT="yes"
TYPE="Ethernet"
PERSISTENT_DHCLIENT=yes



Restart the DHCP server to apply the changes made:

	In the command line type: 
service dhcpd restart








Installing New DHCP package from ISC website

Installing New DHCP package from website
-	 this is to ensure that the latest Omapi functions are added and more stability for DHCP (Not Necessary)
-	Follow these steps and the rest from DHCP package that came with Redhat Linux

  


After editing the network /etc/sysconfig/network-scripts/ifcfg-eth0:
Start and stop DHCP so that the configurations can be applied

	First check if there is any process of DHCP running, if there is kill it:

Look for process: 
ps –ef grep| dhcpd

If there is a process, look for the PID, then kill the process

Kill the process: 
kill -9 <pid>


Start process by specifying location of lease file with -lf:

dhcpd -4 -lf /var/lib/dhcpd/dhcpd.leases


 
Download pypureomapi.py and place into python libraries 

My modified pypureomapi.py file:

	Take my pypureomapi.py file and place into library file:
		
		/usr/lib/python2.6/site-packages/pypureomapi.py
		

Note:
OriginalpPypureomapi.py file:
https://github.com/CygnusNetworks/pypureomapi

-	This is on Github, that is constantly having new functions added that are allowed by omapi
-	If you use this, make change in lookup_ip code:


def lookup_ip(self, mac):
		"""Look for a lease object with given mac address and return the
		assigned ip address.

		@type mac: str
		@rtype: str or None
		@raises ValueError:
		@raises OmapiError:
		@raises OmapiErrorNotFound: if no lease object with the given mac
				address could be found or the object lacks an ip address
		@raises socket.error:
		"""
		msg = OmapiMessage.open(b"lease")
		msg.obj.append((b"hardware-address", pack_mac(mac)))
		response = self.query_server(msg)
		if response.opcode != OMAPI_OP_UPDATE:
			raise OmapiErrorNotFound()
		try:
			return unpack_ip(dict(response.obj)[b"ip-address"])
		except KeyError:  # ip-address
			raise OmapiErrorNotFound()


The highlighted portion should be changed to “host”




Download dhcp.py file 

Download dhcp.py file I provided:

-	Place this file into the folder you will be running it from 
	 
-	First give permission to execute this file without writing python in beginning
o	chmod +x dhcp.py

How to use dhcp.py:
 
This program will add static ip addresses with the mac address in the dhcpd.leases file:

Commands:

	-h = help command giving all possible functions
   		example = ./dhcp.py -h

	-a = add host to dhcpd.leases file with IP (-ip) and MAC (-mac)
   		example = ./dhcp.py -a -ip 61.83.32.201 -mac 00:50:56:9a:00:2b

	-d = delete host from dhcpd.leases file with MAC (-mac)
   		example = ./dhcp.py -mac 00:50:56:9a:00:2b
   
	-l = lookup IP address from MAC (-mac)
   		example = ./dhcp.py -l 00:50:56:9a:00:2b


Note: Make sure to use MAC Address in this format: 00:50:56:9a:00:2b	


	Example:

		Adding =  ./dhcp.py -a -ip 61.83.32.201 -mac 00:50:56:9a:00:2b
		Output = Successfully added host with IP: 61.83.32.201 and MAC: 00:50:56:9a:00:2b
	
			In dhcpd.leases:

host nh55c521ac0112aa20 {
  dynamic;
  hardware ethernet 00:50:56:9a:00:2b;
  fixed-address 61.83.32.201;

		

		Lookup = ./dhcp.py -l -mac 00:50:56:9a:00:2b
		Output = Attempting to lookup host with MAC: 00:50:56:9a:00:2b
The IP Address is 61.83.32.201


Deleting = ./dhcp.py -d -mac 00:50:56:9a:00:2b
			
In dhcpd.leases:


host nh55c521ac0112aa20 {
  dynamic;
  hardware ethernet 00:50:56:9a:00:2b;
  fixed-address 61.83.32.201;
}
server-duid "\000\001\000\001\035V\223\006\000\014)\273\310\023";

host nh55c521ac0112aa20 {
  dynamic;
  deleted;
}

Note: it will still show old host, but the same host is shown deleted below the added one, this acts like a file that logs everything

	


	














	
Controlling DHCP in Windows Server 2012:

-	Run Powershell ISE as administrator
-	Install Tools
-	Server Manager
-	Command Examples



Running Powershell ISE and Installing tools:

Powershell as Administrator

-	Run Powershell ISE as administrator
-	Make sure to use Powershell 3 which comes standard on Windows Server 2012

Installing Tools

Install DHCP and management tools: 
To check:
Get-WindowsFeature | Where-Object Name -like *dhcp* 
To Install:
Install-WindowsFeature DHCP -IncludeManagementTools 

To check changes on Server Manager

-	Go to server manager
-	Under DHCP server, make sure to open up the DHCP server and configure by clicking
o	New window will open up, then take action
o	Click commit
-	Then click on tools on server manager and click on DHCP
o	This opens up DHCP manager
•	There you can see scope and reservation
 
Command Examples in Powershell:

Create a DHCP scope 

Add-DhcpServerv4Scope -Name "Madhav" -StartRange 10.10.10.100 -EndRange 10.10.10.200 -SubnetMask 255.255.255.0  

-Name “<name>”= create a name for this scope
-StartRange <IP address to start with> = IP address, format 10.10.10.100
-EndRange <IP address to end with> = IP address, format 10.10.10.100
-SubnetMask <subnet mask> = example: 255.255.255.0

Get info from DHCP scope 

Get-DhcpServerv4Scope -ScopeId 10.10.10.0 

-ScopeId: for ip address, put last 0 after last decimal 
	Example: StartRange 10.10.10.100 →  10.10.10.0
Ex:
ScopeId         SubnetMask      Name           State    StartRange      EndRange        LeaseDuration                                                                         
-------         ----------      ----           -----    ----------      --------        -------------                                                                         
10.10.10.0      255.255.255.0   Madhav         Active   10.10.10.100    10.10.10.200    8.00:00:00      


Remove DHCP scope 
Remove-DhcpServerv4Scope -ScopeID 10.10.10.0 

Add DHCP reservation
Add-DhcpServerv4Reservation -ScopeId 10.10.10.0 -IPAddress 10.10.10.108 -ClientID F0-DE-F1-7A-00-5E

Get DHCP reservation
Get-DhcpServerv4Reservation -ScopeId 10.10.10.0  

Remove DHCP reservation
Remove-DhcpServerv4Reservation -ScopeId 10.10.10.0 

Get DHCP reservation
Get-DhcpServerv4Reservation -ScopeId 10.10.10.0  

Ex:
IPAddress            ScopeId              ClientId             Name                 Type                 Description         
---------            -------              --------             ----                 ----                 -----------         
10.10.10.108         10.10.10.0           f0-de-f1-7a-00-5e                         Both       


Note: Cannot delete scope if there is a reservation, delete reservation first



