#!/usr/bin/python2.7
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

# username:password for the Soltra Edge server we are polling from
# example: "username:password"
user_pwd = ""

# Directory to store IPs and Domains to be added as firewall rules
# example: "/home/user/soltra-fw-rules/"
outputLocation = ""

# IP address of the Juniper firewall
Juniperip = ""

# SSH username and password for Juniper firewall
Juniperusr = ""
Juniperpwd = ""

# Interface on Firewall
Juniperif = ""

#########################

# Discovery Service URL we are polling from
taxii_url = "https://taxii.cisecurity.org/taxii-discovery-service/"

# IP and domain file output name
outputFile = 'ms-isac.csv'

#Date script is ran for term identification
today = datetime.strftime(datetime.utcnow(),'%Y-%m-%dT%H:%M:%SZ')
today2 = datetime.strftime(datetime.utcnow(),'%Y-%m-%d')

#SOLTRA LOGIN
# If the username:password or output directory is not set, prompt the user for it
if len(user_pwd) < 1:
	user_tmpusr = raw_input('Enter your MS-ISAC Soltra Username -> ')
	user_tmppwd = getpass.getpass(prompt='Enter your MS-ISAC Soltra Password -> ')
	user_pwd = user_tmpusr + ":" + user_tmppwd
if len(outputLocation) < 1:	
	outputLocation = raw_input('Enter your local directory location to store IPs/domains -> ')

#JUNIPER LOGIN
# If the Juniper firewall informaiton is not set, prompt the user for it
if len(Juniperip) < 1:	
	Juniperip = raw_input('Enter the IP address of the Juniper firewall -> ')
if len(Juniperusr) < 1:	
	Juniperusr = raw_input('Enter the SSH username for the Juniper firewall -> ')
if len(Juniperpwd) < 1:	
	Juniperpwd = getpass.getpass(prompt='Enter the SSH password for the Juniper firewall -> ')
if len(Juniperif) < 1:	
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

# Authenticate with Soltra Edge server
# Poll Feed data from the specified time period
# Return buffer of data
def pollData(taxii_url,user_pwd,first):
	# Start of py curl routine
	# Setup poll requrst xml
	xmlstart = """<?xml version="1.0" encoding="UTF-8" ?>"""
	boilerplate = """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xsi:schemaLocation="http://taxii.mitre.org/messages/taxii_xml_binding-1.1 http://taxii.mitre.org/messages/taxii_xml_binding-1.1" """
	message_id = str(random.randint(345271,9999999999))
	# Feed to poll
	feed_name = "admin.AttackingIP"
	# We want to only grab the data from last week to today
	# Get todays date/time
	#today = datetime.strftime(datetime.utcnow(),'%Y-%m-%dT%H:%M:%SZ')
	# Subtract 7 or 30 days from todays date/time depending on if this is the first run or not
	if first is True:
		past = datetime.strftime(datetime.utcnow() - timedelta(days=30), '%Y-%m-%dT%H:%M:%SZ')
	else:
		past = datetime.strftime(datetime.utcnow() - timedelta(days=7), '%Y-%m-%dT%H:%M:%SZ')
	start_end = """
    		<taxii_11:Exclusive_Begin_Timestamp>"""+past+"""</taxii_11:Exclusive_Begin_Timestamp>
    		<taxii_11:Inclusive_End_Timestamp>"""+today+"""</taxii_11:Inclusive_End_Timestamp>"""
	# Poll template
	xml_poll = xmlstart + """
		<taxii_11:Poll_Request {{boilerplate}} message_id="{{message_id}}" collection_name="{{feed_name}}" >
    			<taxii_11:Poll_Parameters allow_asynch="false">
        			<taxii_11:Response_Type>FULL</taxii_11:Response_Type>
        			<taxii_11:Content_Binding binding_id="{{content_binding}}" />
    			</taxii_11:Poll_Parameters>
    			{{start_end}}
		</taxii_11:Poll_Request>"""
	xml = xml_poll.replace('{{boilerplate}}',boilerplate) \
        	      .replace('{{message_id}}',message_id) \
            	      .replace('{{feed_name}}',feed_name) \
             	      .replace('{{start_end}}',start_end) \
            	      .replace('{{content_binding}}',"urn:stix.mitre.org:xml:1.1.1")
	headers = [
		"Content-Type: application/xml",
  		"Content-Length: " + str(len(xml)),
    		"User-Agent: TAXII Client Application",
    		"Accept: application/xml",
    		"X-TAXII-Accept: urn:taxii.mitre.org:message:xml:1.1",
    		"X-TAXII-Content-Type: urn:taxii.mitre.org:message:xml:1.1",
    		"X-TAXII-Protocol: urn:taxii.mitre.org:protocol:https:1.0",
		]
	# Create buffer to store the response
	buf = StringIO.StringIO()
	# Assemble the poll request
	conn = pycurl.Curl()
	conn.setopt(pycurl.URL, taxii_url)
	conn.setopt(pycurl.USERPWD, user_pwd)
	conn.setopt(pycurl.HTTPHEADER, headers)
	conn.setopt(pycurl.POST, 1)
	conn.setopt(pycurl.TIMEOUT, 999999)
	conn.setopt(pycurl.SSL_VERIFYPEER, 0)
	conn.setopt(pycurl.SSL_VERIFYHOST, 0)
	conn.setopt(pycurl.WRITEFUNCTION, buf.write)
	conn.setopt(pycurl.POSTFIELDS, xml)
	# Make the poll request
	conn.perform()
	return buf

# Format attacking IPs for firewall rule generation
def genRule(address,msg,isDomain):
	# If we have an IP address (not a domain) label it as an IP
	if isDomain is False:
		rule = '"ip","' + address + '","' + msg + '","new"'
	# If we have a domain label it as a domain
	elif isDomain is True:
		rule = '"domain","' + address + '","' + msg + '","new"'
	return rule

# Convert stix data to xml tree and pull out information for rules	
def parseStixtoSnort(buf,lastAddr,oldAddrs):
	# List to store rules
	rules = []
	# create xml etree from the buffer data
	try:
		root = lxml.etree.fromstring(buf.getvalue())
	except:
		print "\nSomething went wrong while polling the feed"
		print "Please verify your Username, Password, and Network Connection"
		print "and Try Again"
		exit()
	# Labels for the information we want from the xml etree
	getIP = '{http://cybox.mitre.org/objects#AddressObject-2}Address_Value'
	getDomain = '{http://cybox.mitre.org/objects#DomainNameObject-1}Value'
	getDesc = '{http://cybox.mitre.org/cybox-2}Description'

	# Loop though each top entry in the etree
	for i in root:
		# Iterate through each entry and grab the information we need to make rules
		# isDomain is used my the genRule fuction to decide what kind of rule to make
		for element in i.iter(getIP,getDomain,getDesc):
			if element.tag == getIP:
				isDomain = False
				address = element.text
			elif element.tag == getDomain:
				isDomain = True
				address = element.text
			elif element.tag == getDesc:
				msg = element.text
				# We just want the first line of the description
				msg = msg[msg.index('Threat: ')+len('Threat: '):msg.index('\n')]
			# If the entry had the information we need for a rule
			# Call genRule with the infomornation
			# Append it to the rule list
			if address is not None:
				if (any(address in s for s in oldAddrs)) == False:
					rules.append(genRule(address,msg,isDomain))
		address = None
	return rules

# Write rules to output location
def outputRules(output,rules):
	f = open(output,'a')
	for x in rules:
		f.write(x+'\n')
	f.close()

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
				con.send('set firewall family inet filter MSISAC_Soltra term ' + today2 + ' from destination-address ' + row[1] + '\n')
				time.sleep(.2)

				numnewrules += 1

				# Mark the rule as applied within the rule file to avoid duplicate entries
				row[3] = 'applied'

			if row[0] == "domain":
				# Apply filter
				con.send('set firewall family inet filter MSISAC_Soltra term ' + today2 + ' from destination-address ' + row[1] + '\n')
				time.sleep(.2)

				numnewrules += 1

				# Mark the rule as applied within the rule file to avoid duplicate entries
				row[3] = 'applied'

		#Apply Protocols
		con.send('set firewall family inet filter MSISAC_Soltra term ' + today2 + ' from protocol icmp' + '\n')
		time.sleep(.2)
		con.send('set firewall family inet filter MSISAC_Soltra term ' + today2 + ' from protocol udp' + '\n')
		time.sleep(.2)
		con.send('set firewall family inet filter MSISAC_Soltra term ' + today2 + ' from protocol tcp' + '\n')
		time.sleep(.2)

		#Apply Discard
		con.send('set firewall family inet filter MSISAC_Soltra term ' + today2 + ' then discard' + '\n')
		time.sleep(.2)

		#Apply Counter
		con.send('set firewall family inet filter MSISAC_Soltra term ' + today2 + ' then count MSISAC_Soltra-Counter' + '\n')
		time.sleep(.2)

		#Commit Filter
		con.send('commit' + '\n')
		time.sleep(.2)

		#Set Interfaces
		con.send('set interfaces ' + Juniperif + ' unit 0 family inet filter MSISAC_Soltra' + '\n')
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

# Poll data from Soltra Server
data = pollData(taxii_url,user_pwd,first)

# Create Snort signatures from data
rules = parseStixtoSnort(data,lastAddr,oldAddrs)

# Output signatures to file
outputRules(output,rules)

newrules = applyRules(outputLocation,output,Juniperip,Juniperusr,Juniperpwd)

print 'Applied',str(newrules),'New Firewall Rules'
print 'Written to',output
