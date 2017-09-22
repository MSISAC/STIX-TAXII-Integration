api2juniper

About

api2juniper is a simple python script that converts the MS-ISAC Anomali AttackingIPs feed into firewall filters on your remote Juniper Firewall to block outgoing traffic to malicious IPs and domains.

The AttackingIPs feed contains observables in the form of IP addresses and domains that have been observed as malicious by the MS-ISAC SOC.

The filters created by this script are meant to be applied to an Interface Firewall Filter for egress traffic to the Internet on the Juniper Firewall.

Each occurrence that the script is run, it will log a new term (indicated by the date and time in which it was ran) within a Firewall Filter titled MSISAC_Anomali. This will allow tracking of when IPs and domain were added to the filter, and you/we can easily identify false positives. We have also enabled a counter for the filter to track how many packets that the filter is dropping.

*******************************

We require your public IP address or range(s) to be whitelisted prior to gaining access to the MS-ISAC AttackingIP feed.
If you wish to gain access to the feeds, please email a request to soc|at|msisac.org.

Usage
Ensure topattacking.py is in the same directory as this script.

$ python api2juniper.py
Enter your local directory location to store IPs/domains -> <dir>
Enter the IP address of the Juniper firewall -> <ip>
Enter the SSH username for the Juniper firewall -> <username>
Enter the SSH password for the Juniper firewall -> <password>
Enter the Interface for the Juniper firewall -> <interface>

These prompts can be avoided by adding this information to the script itself just under the import section near the top of the file:

#########################
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


On the first run, this script will convert all observables from the AttackingIPs feed in the last month to firewall rules.
Each run after the initial will convert observables from the last 7 days.

This is intended to be added to your a system as a cron job to be run each week in order to add the newest malicious IP addresses and domains to your firewall rules.

This can be done by adding the following to your crontab:
$ crontab -e

append this line to run api2juniper every Tuesday at midnight:
0 0 * * 2 python /path/to/api2juniper.py