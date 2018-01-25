import requests
import datetime
import json
import os
import time

class api():
	def __init__(self):
		self.domains = "http://54.244.134.70/api/domains"
		self.ips = "http://54.244.134.70/api/ips"
		self.current_time = datetime.datetime.now()

	def getInfo(self, boolean):
		try:
			if boolean == True:
				d = requests.get(self.domains, timeout=10)
				i = requests.get(self.ips, timeout=10)
			else:
				lastrun = datetime.datetime.strftime(self.current_time - datetime.timedelta(days=10), '%Y%m%d')
				d = requests.get(self.domains + "/" + lastrun, timeout=10)
				i = requests.get(self.ips + "/" + lastrun , timeout=10)

			domains = d.json()
			ips = i.json()
			info = domains + ips
			info_list = []
			for line in domains:
				info_list.append(line)
			for line in ips:
				info_list.append(line)
				
			return info_list

		except requests.exceptions.Timeout:
			print "ERROR: TIMEOUT! Check If You Are Whitelisted with the MS-ISAC. Please Contact indicator.sharing|at|cisecurity.org"
