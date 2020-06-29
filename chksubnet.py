#!/usr/bin/python
import os
import io
import sys
import re
import argparse

DEBUGMODE=False

ipPrefix = "([0-9]{1,3}\.){3}([0-9]{1,3})"

ipexpr = re.compile("^" + ipPrefix + "$")
cidrexpr = re.compile("^" + ipPrefix + "\/[0-9]{1,2}$")

#
# Test Function for debugging, use -t to call
#
def Test(parameter):
	x=ConvertFromIPv4("192.168.0.0")
	y=ConvertFromIPv4("255.255.0.0")
	print(ToIPv4CIDR(x,y))

#
# Convert IPv4 String to 32bit integer
#
def ConvertFromIPv4(addr):
	quads = addr.split(".")

	value = 0
	value = int(quads[0]) << 24
	value = value + (int(quads[1]) << 16)
	value = value + (int(quads[2]) << 8)
	value = value + int(quads[3])

	return value

#
# Convert 32bit Integer Into IPv4 String
#
def IntToIPv4(addr):
	quads = ""

	quads = str((addr >> 24) & 0xff) + "."
	quads = quads + str((addr >> 16) & 0xff) + "."
	quads = quads + str((addr >> 8) & 0xff) + "."
	quads = quads + str(addr & 0xff)

	return quads

#
# Convert 32bit Integer representing IPv4 Network and netmask length into a CIDR notation
#
def ToIPv4CIDR(addr,bits):
	if bits > 32:
		# Bits given as netmask (as integer)

		# Xor out the high order bits, leaving the bits lower bits
		x=0xffffffff^bits

		# Only count the lower order bits (most CIDRs will be 16 or higher
		# therefore there should be a savings in looping when evaluating a large
		# number of 16 through 32 bit masks. If the masks are 0 to 16, we ending
		# end up spending more time looping though.
		bds=0
		while x > 0:
			bds=bds+1
			x=x>>0x01

		# Take the bit count, subtract it from 32
		bds=32-bds

		addr = IntToIPv4(addr) + "/" + str(bds)
	else:
		addr = IntToIPv4(addr) + "/" + str(bits)

	return addr

#
# Convert A IPv4 CIDR String into a CIDR Tuple (32bit network, 32bit netmask, significant bits in mask)
#
def ConvertFromIPv4CIDR(cidraddr):
	processed = [ 0,0,0 ]

	data = cidraddr.split("/")

	bm = int(data[1])

	nm = (0xffffffff << (32 - bm))

	value = ConvertFromIPv4(data[0])

	processed[0] = value
	processed[1] = nm
	processed[2] = bm

	return processed

#
# Given Subnet/CIDR tuple and IP, See if the IP is within the network
#
def WithinSubnet(subnet,ip):
	return ip & subnet[0] == subnet[0]

#
# Print Debug Messages, If In Debug Mode
#
def DbgMsg(mesg):
	if DEBUGMODE:
		print(mesg)

#
# Main Loop for Scripting
#

if __name__ == "__main__":
	# Get and Parse Cmdline Args
	parser = argparse.ArgumentParser()

	parser.add_argument("ip", help="IP to compare against subnet(s)")
	parser.add_argument("subnet", help="Subnet in CIDR")
	parser.add_argument("-q","--quiet", action="store_true", default=False, help="Be silent when processing")
	parser.add_argument("-d","--debug", action="store_true", default=False, help="Enter debug mode")
	parser.add_argument("-t","--test", action="store_true", default=False, help="Execute test function")
	args = parser.parse_args()

	# Set DebugMode
	DEBUGMODE=args.debug

	if args.test:
		Test("")

	# If subnet param is a file, assume the file contains CIDR and IP addresses, one per line, read in
	# and compare, exit when first found.
	if os.path.exists(args.subnet):
		DbgMsg("ip file check")

		# Convert IPv4 String to 32bit integer
		ipaddr = ConvertFromIPv4(args.ip)

		# Open file of CIDR patterns
		with open(args.subnet,"r") as patterns:
			# Go through each pattern
			for line in patterns:
				line = line.rstrip()

				# If an IP, compare IPs
				if ipexpr.match(line):
					if line == args.ip:
						if not args.quiet:
							print(args.ip + " is in " + line)

						exit (0)
					else:
						if not args.quiet:
							print(args.ip + " is not in " + line)
				else:
					# Falling ito this else, the line is a CIDR string

					# Convert CIDR into CIDR Tuple
					subnet = ConvertFromIPv4CIDR(line)

					# Check if IP with within network
					if WithinSubnet(subnet,ipaddr):
						if not args.quiet:
							print(args.ip + " is in " + line)

						exit (0)
					else:
						if not args.quiet:
							print(args.ip + " is not in " + line)
	else:
		# Falling into this else, arguments are IP and SUBNET
		DbgMsg("ip subnet check")

		# Make sure both args fit the correct pattern
		if not ipexpr.match(args.ip) or not cidrexpr.match(args.subnet):
			DbgMsg("Either IP is not IP ("+ args.ip + ") or subnet is not SUBNET (" + args.subnet +")")
			exit(2)

		# Since both are correct format, lets do this... convert them :)
		subnet = ConvertFromIPv4CIDR(args.subnet)
		ipaddr = ConvertFromIPv4(args.ip)

		# Check IP against subnet
		if WithinSubnet(subnet,ipaddr):
			if not args.quiet:
				print(args.ip + " is in " + args.subnet)

			exit (0)
		else:
			if not args.quiet:
				print(args.ip + " is not in " + args.subnet)

	exit (1)
