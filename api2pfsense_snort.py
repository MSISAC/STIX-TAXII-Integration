#!/usr/bin/python2.7
import topattacking
import os
import json
import re

### EDIT THIS SECTION ###
# Snort rule directory
# example: "/usr/local/etc/snort/rules/"
outputLocation = ""

# Signature file output name
outputFile = 'snort_local.rules'
#########################

#Output Directory
if len(outputLocation) < 1:	
	outputLocation = raw_input('Enter your local directory location to store IPs/domains -> ')

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

	else:
		# Return if no output file exists
		return output,True,None,''


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

def api(output, first, lastSid):
	api = topattacking.api()

	if lastSid is None:
		sid = 1000000
	else:
		sid = int(lastSid)

	if first == True:
		info = api.getInfo(True)
		file = open(output, "w")

		for line in info:
			if 'domain' in line:
				line_value = line['domain']
			if 'ip' in line:
				line_value = line['ip']

			msg = ""
			if re.match( '(?:[0-9]{1,3}\.){3}[0-9]{1,3}', line_value ):
				sig = genSnort(line_value, msg, False, str(sid))
				file.write(sig + "\n")
				sid += 1

		file.close()
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
			
			if re.match( '(?:[0-9]{1,3}\.){3}[0-9]{1,3}', line_value ):
				sig = genSnort(line_value, msg, False, str(sid))
				file.write(sig + "\n")
				sid += 1
		file.close()

#Check to see if output file exists
output,first,lastSid,oldSigs = verifyOutFile(outputLocation,outputFile)

#Pull Domains and IPs from API and 
api(output, first, lastSid)