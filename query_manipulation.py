#!/usr/bin/python
# -*- coding: utf8 -*-
#query_manipulation.py



__author__ = "Madhav Agrawal"



import sys
import pypureomapi
import re

# Checks if IP Address given is valid. Returns empty string if it is valid.
def isValidIP(ip_address):
	ip_parts = ip_address.split(".")
	if(len(ip_parts) != 4):
		return "This is not a valid IP Address. A valid one's format is XXX.XXX.XXX.XXX"
	else:
		for part in ip_parts:
			if not part.isdigit():
				return "The IP Address can only contain periods and numbers."
		return ""

# Checks if MAC Address given is valid. Returns empty string if it is valid.
def isValidMAC(mac_address) :
	if mac_address == "":
		return "The MAC Address cannot be left as empty"
	else:
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac_address.lower()):
			return ""
		return "This is not a valid MAC Address. A valid one's format is XX:XX:XX:XX:XX:XX"

# Connects to Omapi
def connectOmapi():
	keyname = "jpm_key"
	secret = "8keHkH9a4orx/k9AZWiEhQ=="
	server = "127.0.0.1"
	port = 7911

	try:
		oma = pypureomapi.Omapi(server, port, keyname, secret)
		return oma
	except pypureomapi.OmapiError as err :
		print ("OMAPI error: %s" % (err))
		sys.exit(1)

# Attempts to add the host, but first checks if the inputs are valid
def addHost(arguments):
	if len(arguments) != 6:
		print "The number of arguments is incorrect, the command should look like:"
		print "./dhcpHelp.py -a -ip 61.83.31.201 -mac 00:50:56:9a:00:2b"
	else:
		ip_address = ""
		if (arguments[2] == "-ip"):
			ip_address = arguments[3]
			validIP = isValidIP(ip_address)
			if (validIP != ""):
				print validIP
			else:
				mac_address = ""
				if (arguments[4] == "-mac"):
					mac_address = arguments[5]
					validMAC = isValidMAC(mac_address)
					if (validMAC == ""):
						#omapi add function
						print "Attempting to add host with IP: " + ip_address + " and MAC: " + mac_address
						oma = connectOmapi()
						try:
							oma.add_host(ip_address, mac_address.lower())
							print "Successfully added host with IP: " + ip_address + " and MAC: " + mac_address
						except Exception, e:
							print e
					else:
						print validMAC
				else:
					print "The argument for MAC Address is missing"
		else:
			print "The argument for IP Address is missing"

# Attempts to delete the host, but first checks if the inputs are valid
def deleteHost(arguments):
	if len(arguments) != 4:
		print "The number of arguments is incorrect, the command should look like:"
		print "./dhcpHelp.py -d -mac 00:50:56:9a:00:2b"
	else:
		mac_address = ""
		if (arguments[2] == "-mac"):
			mac_address = arguments[3]
			validMAC = isValidMAC(mac_address)
			if (validMAC == ""):
				#omapi delete function
				print "Attempting to delete host with MAC: " + mac_address
				oma = connectOmapi()
				try:
					oma.del_host(mac_address.lower())
					print "Successfully deleted host with MAC: " + mac_address
				except Exception, e:
					print e
			else:
				print validMAC
		else:
			print "The argument -mac is missing, the command should look like:"
			print "./dhcpHelp.py -d -mac 00:50:56:9a:00:2b"

# Attempts to lookup the host, but first checks if the inputs are valid
def lookupHost(arguments):
	if len(arguments) != 4:
		print "The number of arguments is incorrect, the command should look like:"
		print "./dhcpHelp.py -l -mac 00:50:56:9a:00:2b"
	else:
		mac_address = ""
		if (arguments[2] == "-mac"):
			mac_address = arguments[3]
			validMAC = isValidMAC(mac_address)
			if (validMAC == ""):
				#omapi lookup function
				print "Attempting to lookup host with MAC: " + mac_address
				oma = connectOmapi()
				try:
					lookup_output = oma.lookup_ip(mac_address.lower())
					print "The IP Address is " + lookup_output
				except Exception, e:
					print e
			else:
				print validMAC
		else:
			print "The argument -mac is missing, the command should look like:"
			print "./dhcpHelp.py -l -mac 00:50:56:9a:00:2b"

# prints the help information
def printHelp():
	help_str = """

	-h = help command giving all possible functions
		example = ./dhcp.py -h

	-a = add host to dhcpd.leases file with IP (-ip) and MAC (-mac)
		example = ./dhcp.py -a -ip 61.83.32.201 -mac 00:50:56:9a:00:2b

	-d = delete host from dhcpd.leases file with MAC (-mac)
		example = ./dhcp.py -mac 00:50:56:9a:00:2b

	-l = lookup IP address from MAC (-mac)
		example = ./dhcp.py -l 00:50:56:9a:00:2b
	"""
	print(help_str)

def main():
	arguments = sys.argv
	if len(arguments) == 1:
		print "Arguments are needed. To see help, run ./dhcpHelp.py -h"
	else:
		if (arguments[1] == "-a"):
			addHost(arguments)

		elif (arguments[1] == "-d"):
			deleteHost(arguments)

		elif (arguments[1] == "-l"):
			lookupHost(arguments)

		elif (arguments[1] == "-h"):
			printHelp()

		else:
			print "\n The arguments given are invalid. Below is the correct way to give arguments:"
			printHelp()


if __name__ == '__main__':
	main()
