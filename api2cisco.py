#!/usr/bin/python2.7
import topattacking
import os
import pycurl
import random
import getpass
import StringIO
import lxml.etree
from datetime import datetime, timedelta
import csv
import paramiko
from tempfile import NamedTemporaryFile
import shutil
import time

### EDIT THIS SECTION ###

# Directory to store IPs and Domains to be added as firewall rules
# example: "/home/user/anomali-fw-rules/"
outputLocation = ""

# IP address of the Cisco firewall
ciscoip = ""

# SSH username and password for Cisco firewall
ciscousr = ""
ciscopwd = ""

# enable password for Cisco firewall
ciscoenablepwd = ""

# name or number of extend ACL on Cisco firewall
ciscoacl = ""

#########################

# IP and domain file output name
outputFile = 'ms-isac.csv'

if len(outputLocation) < 1:	
	outputLocation = raw_input('Enter your local directory location to store IPs/domains -> ')

# If the Cisco firewall informaiton is not set, prompt the user for it
if not ciscoip:	
	ciscoip = raw_input('Enter the IP address of the Cisco firewall -> ')
if not ciscousr:	
	ciscousr = raw_input('Enter the SSH username for the Cisco firewall -> ')
if not ciscopwd:	
	ciscopwd = getpass.getpass(prompt='Enter the SSH password for the Cisco firewall -> ')
if not ciscoenablepwd:	
	ciscoenablepwd = getpass.getpass(prompt='Enter the enable password for the Cisco firewall -> ')
if not ciscoacl:	
	ciscoacl = raw_input('Enter the ACL number to apply the rules to -> ')

# Check to see if the output files exists
# If it does, grab old addresses to avoid duplication
def verifyOutFile(outputLocation,outputFile):
	# Check if the output directory ends in a /
	# If not, add a /
	if outputLocation[-1] is not '/':
		outputLocation = outputLocation+'/'
	# Check if the output directory exists
	# If not, exit
	if os.path.isdir(outputLocation) is False:
		print 'Path:',outputLocation,'does not exist'
		exit()
	output = outputLocation+outputFile
	# Does output file exist
	if os.path.isfile(output):
		f = open(output,'r')
		oldAddrs = f.readlines()
		# Get the last ip/domain
		lastAddr = oldAddrs[-1]
		return output,False,lastAddr,oldAddrs
	# Return if no output file exists
	else:
		return output,True,None,''

# Format attacking IPs for firewall rule generation
def genRule(address,msg,isDomain):
	# If we have an IP address (not a domain) label it as an IP
	if isDomain is False:
		rule = '"ip","' + address + '","' + msg + '","new"'
	# If we have a domain label it as a domain
	elif isDomain is True:
		rule = '"domain","' + address + '","' + msg + '","new"'
	return rule

def api(output, first):
	api = topattacking.api()
	if first == True:
		file = open(output, "w")
		info = api.getInfo(True)
	else:
		file = open(output, "a")
		info = api.getInfo(False)

	for line in info:
		if 'domain' in line:
			line_value = line['domain']
			msg = "MS-ISAC MALWARE DOMAIN"
		if 'ip' in line:
			line_value = line['ip']
			msg = "MS-ISAC MALWARE IP"

		sig = utils.genRule(line_value, msg, False)
		file.write(sig + "\r\n")
	file.close()

# Apply firewall rules to the Cisco firewall
def applyRules(outputLocation,output,ciscoip,ciscousr,ciscopwd,ciscoenablepwd,ciscoacl,aclcount):
	numnewrules = 0

	# Set up the SSH client to connect to the Cisco firewall
	con_pre=paramiko.SSHClient()
	con_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	con_pre.connect(ciscoip, username=ciscousr, password=ciscopwd,look_for_keys=False, allow_agent=False)

	# Connect to the Cisco firewall via SSH
	con = con_pre.invoke_shell()
	
	con.send('enable\n')
	time.sleep(.2)
	con.send(ciscoenablepwd + '\n')
	
	# Enter global configuration mode
	time.sleep(.2)
	con.send('config t' + '\n')

	# Edit the current access-list
	time.sleep(.2)
	con.send('ip access-list extended ' + ciscoacl  + '\n')
	sshoutput = con.recv(65535)
	
	# Open the rule file
	f = open(output, 'rb')
	reader = csv.reader(f, delimiter=',', quotechar='"')
 
	# Open the rule file and create a temporary file to store the applied firewall rules
	tf = NamedTemporaryFile(delete=False)
	writer = csv.writer(tf, delimiter=',', quotechar='"')

	# Loop through each row of the rule file to get IP addresses
	for row in reader:

		# Check if the rule is new
		if row[3] == 'new':
			time.sleep(.2)

			# If the rule is for an IP address, format the ACL appropriatly and apply it to the firewall's configuration
			if row[0] == "ip":

				# Apply ACL
				con.send(str(aclcount) + ' deny ip any host ' + row[1] + '\n')

				# Increment the number of new rules applied count and the acl count
				aclcount += 1
				numnewrules += 1

				# Mark the rule as applied within the rule file to avoid duplicate entries
				row[3] = 'applied'

			if row[0] == "domain":
				
				# Exit ACL configuration mode
				time.sleep(.2)
				con.send('exit' + '\n')

				# Create network object
				time.sleep(.2)
				con.send('object network obj-' + row[1] + '\n')

				# Add FQDN
				time.sleep(.2)
				con.send('fqdn ' + row[1] + '\n')

				# Edit the current access-list
				time.sleep(.2)
				con.send('ip access-list extended ' + ciscoacl  + '\n')

				# Apply ACL
				time.sleep(.2)
				con.send(str(aclcount) + ' deny ip any object obj-' + row[1] + '\n')
				
				# Increment the number of new rules applied count and the acl count
				aclcount += 1
				numnewrules += 1

				# Mark the rule as applied within the rule file to avoid duplicate entries
				row[3] = "applied"

		# Write the rules to the temporary file
		writer.writerow(row)

	# Replace the old rule file with the temporary file that has the updated 'applied' rules
	shutil.move(tf.name, output) 
	f.close()
	
	return numnewrules

# Check to see if output file exists
output,first,lastAddr,oldAddrs = verifyOutFile(outputLocation,outputFile)

api(output, first)

# Keep track of the ACL number
aclcount = len(oldAddrs) + 1

newrules = applyRules(outputLocation,output,ciscoip,ciscousr,ciscopwd,ciscoenablepwd,ciscoacl,aclcount)		    	

print 'Applied',str(newrules),'New Firewall Rules'

print 'Written to',output