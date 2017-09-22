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

# IP address of the Juniper firewall
Juniperip = ""

# SSH username and password for Juniper firewall
Juniperusr = ""
Juniperpwd = ""

# Interface on Firewall
Juniperif = ""

#########################

# IP and domain file output name
outputFile = 'ms-isac.csv'

#Date script is ran for term identification
today = datetime.strftime(datetime.utcnow(),'%Y-%m-%dT%H:%M:%SZ')
today2 = datetime.strftime(datetime.utcnow(),'%Y-%m-%d')

#Output Directory
if len(outputLocation) < 1:	
	outputLocation = raw_input('Enter your local directory location to store IPs/domains -> ')

#JUNIPER LOGIN
# If the Juniper firewall informaiton is not set, prompt the user for it
if not Juniperip:	
	Juniperip = raw_input('Enter the IP address of the Juniper firewall -> ')
if not Juniperusr:	
	Juniperusr = raw_input('Enter the SSH username for the Juniper firewall -> ')
if not Juniperpwd:
	Juniperpwd = getpass.getpass(prompt='Enter the SSH password for the Juniper firewall -> ')
if not Juniperif:
	Juniperif = raw_input('Enter the Interface for the Juniper firewall -> ')

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
		info = api.getInfo(True)
		file = open(output, "w")		
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

		if first == True:
			sig = genRule(line_value, msg, True)
		else:
			sig = genRule(line_value, msg, False)

		file.write(sig + "\r\n")

	file.close()
		

# Apply firewall rules to the Juniper firewall
def applyRules(outputLocation,output,Juniperip,Juniperusr,Juniperpwd):
	numnewrules = 0

	# Set up the SSH client to connect to the Juniper firewall
	con_pre=paramiko.SSHClient()
	con_pre.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	con_pre.connect(Juniperip, username=Juniperusr, password=Juniperpwd,look_for_keys=False, allow_agent=False)
	
	# Connect to the Juniper firewall via SSH
	con = con_pre.invoke_shell()

	# Enter cli
	con.send('cli\n')
	time.sleep(.2)

	# Enter config
	con.send('configure\n')
	time.sleep(.2)

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
			# If the rule is for an IP address, format the filter appropriatly and apply it to the firewall's configuration
			if row[0] == "ip":
				# Apply filter
				con.send('set firewall family inet filter MSISAC_Anomali term ' + today2 + ' from destination-address ' + row[1] + '\n')
				time.sleep(.2)

				numnewrules += 1

				# Mark the rule as applied within the rule file to avoid duplicate entries
				row[3] = 'applied'

			if row[0] == "domain":
				# Apply filter
				con.send('set firewall family inet filter MSISAC_Anomali term ' + today2 + ' from destination-address ' + row[1] + '\n')
				time.sleep(.2)

				numnewrules += 1

				# Mark the rule as applied within the rule file to avoid duplicate entries
				row[3] = 'applied'

		#Apply Protocols
		con.send('set firewall family inet filter MSISAC_Anomali term ' + today2 + ' from protocol icmp' + '\n')
		time.sleep(.2)
		con.send('set firewall family inet filter MSISAC_Anomali term ' + today2 + ' from protocol udp' + '\n')
		time.sleep(.2)
		con.send('set firewall family inet filter MSISAC_Anomali term ' + today2 + ' from protocol tcp' + '\n')
		time.sleep(.2)

		#Apply Discard
		con.send('set firewall family inet filter MSISAC_Anomali term ' + today2 + ' then discard' + '\n')
		time.sleep(.2)

		#Apply Counter
		con.send('set firewall family inet filter MSISAC_Anomali term ' + today2 + ' then count MSISAC_Anomali-Counter' + '\n')
		time.sleep(.2)

		#Commit Filter
		con.send('commit' + '\n')
		time.sleep(.2)

		#Set Interfaces
		con.send('set interfaces ' + Juniperif + ' unit 0 family inet filter MSISAC_Anomali' + '\n')
		time.sleep(.2)

		#Commit Filter to Interfaces
		con.send('commit' + '\n')
		time.sleep(.2)

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

newrules = applyRules(outputLocation,output,Juniperip,Juniperusr,Juniperpwd)

print 'Applied',str(newrules),'New Firewall Rules'
print 'Written to',output