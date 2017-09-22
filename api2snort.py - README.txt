api2snort

About

api2snort is a simple python script that converts the MS-ISAC Anomali AttackingIPs feed into a Snort rules file for your local Snort instance.

The AttackingIPs feed contains observables in the form of IP addresses and domains that have been observed as malicious by the MS-ISAC SOC.

The rules created by this script are of two types:
1. Any traffic to or from the $Home_Net and the malicious IP addresses
2. DNS queries from the $Home_Net to any address for the malicious domains

We require your public IP address or range(s) to be whitelisted prior to gaining access to the MS-ISAC AttackingIP feed.
If you wish to gain access to the feeds, please email a request to soc|at|msisac.org.

Usage

$ python api2snort.py
Enter your local directory location to store IPs/domains -> <dir>

This prompt can be avoided by adding this information to the script itself just under the import section near the top of the file

### EDIT THIS SECTION ###
# Snort rule directory
# example: "/etc/snort/rules/"
outputLocation = ""

# Signature file output name
outputFile = 'ms-isac.rules'
#########################

In order for Snort to use the rules created by this script, the rules file needs to be added to the snort.conf file on your Snort system. 

Add this line to your snort.conf file:
Import /path/to/file/ms-isac.rules

On the first run, this script will convert all observables from the AttackingIPs feed in the last month to Snort rules.
Each run after the initial will convert observables from the last 7 days.

This is intended to be added to your Snort system as a cron job to be run each week in order to add the newest malicious IP addresses and domains to your Snort rule set.

This can be done by adding the following to your crontab:
$ crontab -e

Append this line to run api2snort every Tuesday at midnight:
0 0 * * 2 python /path/to/api2snort.py

It is a good idea to verify that the user’s crontab containing this job has access to the Snort rules directory.