api2cisco

About

api2cisco is a simple python script that converts the MS-ISAC Anomali AttackingIPs feed into firewall rules for your remote Cisco Firewall to block outgoing traffic to malicious IPs and domains.

The AttackingIPs feed contains observables in the form of IP addresses and domains that have been observed as malicious by the MS-ISAC SOC.

The rules created by this script are meant to be applied to an Extended Access Control List for egress traffic to the Internet on the Cisco Firewall.

****Important****
It is important to confirm the last line in the firewall's ACL contains a permit for all traffic so all outgoing Internet traffic is not blocked.

eg.
Router#config t
Router(config)#ip access-list extended 123
Router(config)#2147483647 permit ip any any
*****************

We require your public IP address or range(s) to be whitelisted prior to gaining access to the MS-ISAC AttackingIP feed.
If you wish to gain access to the feeds, please email a request to soc|at|msisac.org.

Usage
Ensure topattacking.py is in the same directory as this script.

$ python api2cisco.py
Enter your local directory location to store IPs/domains -> <dir>
Enter the IP address of the Cisco firewall -> <ip>
Enter the SSH username for the Cisco firewall -> <username>
Enter the SSH password for the Cisco firewall -> <password>
Enter the enable password for the Cisco firewall -> <password>
Enter the ACL number to apply the rules to -> <acl number>

These prompts can be avoided by adding this information to the script itself just under the import section near the top of the file:

#########################
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


On the first run, this script will convert all observables from the AttackingIPs feed in the last month to firewall rules.
Each run after the initial will convert observables from the last 7 days.

This is intended to be added to your a system as a cron job to be run each week in order to add the newest malicious IP addresses and domains to your firewall rules.

This can be done by adding the following to your crontab:
$ crontab -e

append this line to run api2snort every Tuesday at midnight:
0 0 * * 2 python /path/to/api2cisco.py