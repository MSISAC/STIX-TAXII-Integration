#!/usr/bin/python2.7
import os
import pycurl
import random
import getpass
import StringIO
import lxml.etree
from datetime import datetime, timedelta

### EDIT THIS SECTION ###

# username:password for the Soltra Edge server we are polling from
# example: "username:password"
user_pwd = ""

# Snort rule directory
# example: "/etc/snort/rules/"
outputLocation = ""

#########################


# Discovery Service URL we are polling from
taxii_url = "https://taxii.cisecurity.org/taxii-discovery-service/"

# Signature file output name
outputFile = 'ms-isac.rules'

# If the username:password or output directory is not set, prompt the user for it
if len(user_pwd) < 1:
	user_tmpusr = raw_input('Enter your MS-ISAC Soltra Username -> ')
	user_tmppwd = getpass.getpass(prompt='Enter your MS-ISAC Soltra Password -> ')
	user_pwd = user_tmpusr + ":" + user_tmppwd
if len(outputLocation) < 1:	
	outputLocation = raw_input('Enter your Snort rules directory location -> ')

# Check to see if the output files exists
# If it does, grab old addresses to avoid duplication and last sid
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
		old = f.readlines()
		# Get the last sid
		lastSid = old[-1]
		lastSid = lastSid[lastSid.index('sid:')+4:]
		lastSid = lastSid[:lastSid.index(';')]
		# Get old addresses to avoid duplication later
		oldSigs = []
		for sig in old:
			if 'Domain:' in sig:
				address = sig[sig.index('Domain: ')+8:]
				address = address[:address.index(' ')]
			else:
				address = sig[sig.index('IP: ')+4:]
				address = address[:address.index(' ')]
			oldSigs.append(address)
		return output,False,lastSid,oldSigs
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
	today = datetime.strftime(datetime.utcnow(),'%Y-%m-%dT%H:%M:%SZ')
	# Subtract 7 or 365 days from todays date/time depending on if this is the first run or not
	if first is True:
		past = datetime.strftime(datetime.utcnow() - timedelta(days=365), '%Y-%m-%dT%H:%M:%SZ')
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

# Create and return Snort signature
def genSnort(address,msg,isDomain,sid):
	# Basic Snort signature template
	snort_temp = "alert {{src}} <> {{dst}} (msg:\"MS-ISAC MALWARE {{msg}}\"; {{other}} priority:5;)"
	# If we have an IP address (not a domain)
	# Make a signature to detect any traffic to or from the $HOME_NET and the malicious IP
	if isDomain is False:
		sig = snort_temp.replace('{{src}}','ip $HOME_NET any') \
				.replace('{{dst}}',address+' any') \
				.replace('{{msg}}','IP: '+address+' '+msg) \
				.replace('{{other}}','sid:'+sid+';')
	# If we have a domain
	# Make a signature to detect DNS queries from the $HOME_NET for the malicious domain
	elif isDomain is True:
		add = address.split('.')
		domainContent = ''
		for i in add:
			domainContent += "content:\""+i+"\"; "
		sig = snort_temp.replace('{{src}}','udp $HOME_NET any') \
				.replace('{{dst}}','any 53') \
				.replace('<>','->') \
				.replace('{{msg}}', 'Domain: '+address+' '+msg) \
				.replace('{{other}}', 'content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; '+domainContent+'sid:'+sid+';')
	return sig

# Convert stix data to xml tree and pull out information for signatures	
def parseStixtoSnort(buf,lastSid,oldSigs):
	# List to store signatures
	signatures = []
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
	# Startinig snort sid
	# Locally created sids are supposed to start at 1,000,000
	if lastSid is None:
		sid = 1000000
	else:
		sid = int(lastSid)
	# Loop though each top entry in the etree
	for i in root:
		# Iterate through each entry and grab the information we need to make signatures
		# isDomain is used my the genSnort fuction to decide what kind of signature to make
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
			# If the entry had the information we need for a signature
			# Call genSnort with the infomornation
			# Append it to the signature list
			# Increment the sid by 1
			if address is not None:
				if address not in oldSigs:
					signatures.append(genSnort(address,msg,isDomain,str(sid)))
					sid += 1
		address = None
	return signatures

# Write signatures to output location
def outputSignatures(output,sigs):
	f = open(output,'a')
	for x in sigs:
		f.write(x+'\n')
	f.close()

# Check to see if output file exists
output,first,lastSid,oldSigs = verifyOutFile(outputLocation,outputFile)

# Poll data from Soltra Server
data = pollData(taxii_url,user_pwd,first)

# Create Snort signatures from data
signatures = parseStixtoSnort(data,lastSid,oldSigs)

# Output signatures to file
outputSignatures(output,signatures)

print 'Generated',str(len(signatures)),'New Snort Signatures'
print 'Written to',output
