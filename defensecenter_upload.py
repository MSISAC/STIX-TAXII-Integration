#!/usr/bin/python

# DefenseCenter Snort Uploader - Automatic upload of snort rules in SourceFire Defense Center
#
# Copyright (C) 2016 Thomas Hilt
# Copyright (C) 2016 Scott Parish
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchElementException
import time
import getpass

### EDIT THIS SECTION ###

# Defense Center username
dcuser = ""

# Defense Center password
dcpass = ""

# Defense Center IP/domain name
dcip = ""

# Defense Center Intrusion Policy UUID to place the rules to
dcuuid = ""

# Snort rules file full path
snortfile = ""

#This section is optional. If you encounter certificate issues, permanently add the DC certificate to your browser and set the directory of the Firefox Profile 
# Example: profile = webdriver.FirefoxProfile('/home/user/.mozilla/firefox/wa84ceto.default')
profile = webdriver.FirefoxProfile()

#########################

# Check if username, password, IP address, UUID, and file path are set. If not, prompt the user for them.
if len(dcuser) < 1:
	dcuser = raw_input('Enter your Defense Center Username -> ')
if len(dcpass) < 1:
	dcpass = getpass.getpass(prompt='Enter your Defense Center Password -> ')
if len(dcip) < 1:
	dcip = raw_input('Enter the IP address of the Defense Center -> ')
if len(dcuuid) < 1:
	dcuuid = raw_input('Enter the UUID of the Intrusion Policy -> ')
if len(snortfile) < 1:	
	snortfile = raw_input('Enter the full file path to your Snort rules file -> ')


SNORT_FILE_PATH = snortfile
SNORT_FILE_NAME = SNORT_FILE_PATH.split("/")[-1]


# Open Firefox using the the specified Firefox profile
driver = webdriver.Firefox(profile)

# Function to login to the Defense Center using the username and password provided
def Authentication(user,password):
    driver.get("https://" + dcip)
    time.sleep(2)
    elem = driver.find_element_by_id("username")
    elem.send_keys(user)
    time.sleep(2)
    elem2 = driver.find_element_by_id("password")
    elem2.send_keys(password)
    time.sleep(2)
    elem3 = driver.find_element_by_name("logon")
    elem3.submit()
    time.sleep(2)


try:
    # Authenticate to the Defense Center
    Authentication(dcuser, dcpass)

    # Navigate to the snort rule import page
    time.sleep(20)
    driver.get("https://" + dcip + "/DetectionPolicy/rules/rulesimport.cgi")
    time.sleep(2)
    elem4 = driver.find_element_by_xpath("/html/body/div[6]/div[3]/form[1]/div/table/tbody/tr[3]/td/input[1]")
    elem4.click()
    time.sleep(2)

    # Upload the snort rule file
    elem5 = driver.find_element_by_xpath("/html/body/div[6]/div[3]/form[1]/div/table/tbody/tr[3]/td/input[2]")
    elem5.send_keys(SNORT_FILE_PATH)
    time.sleep(2)
    elem6 = driver.find_element_by_xpath("/html/body/div[6]/div[3]/form[1]/div/table/tbody/tr[5]/td[2]/input")
    elem6.click()
    time.sleep(40)

except Exception:
    print 'Failed to load last SNORT rules in ' + SNORT_FILE_NAME + ' (navigation problem)'
    driver.close()
    exit()

# Check to see if the snort rule file was succesfully uploaded or not
try:
    notifmsg = driver.find_element_by_xpath("/html/body/div[6]/div[3]/div[2]/div")
    if 'Error' in notifmsg.get_attribute('innerHTML'):
        raise Exception("Error","Bad Snort file.")

except NoSuchElementException: #Normal behaviour (no error message displayed)
    driver.close()
    time.sleep(10)

except Exception:
    print 'Failed to load last SNORT rules in ' + SNORT_FILE_NAME + '. Some rules are bad.'
    driver.close()
    exit()

# Open Firefox using the the specified Firefox profile
driver = webdriver.Firefox(profile)

try:
    
    # Authenticate to the Defense Center
    Authentication(dcuser, dcpass)

    # Navigate to the intrusion policy
    driver.get('https://' + dcip + '/DetectionPolicy/ids.cgi?uuid=' + dcuuid + '#rules')
    time.sleep(50)
    
    # Locate all the uploaded rules and apply them to the Intrusion Policy.
    elem7 = driver.find_element_by_class_name("filterTextBox")
    elem7.send_keys('Message:"MS-ISAC MALWARE"')
    elem7.send_keys(Keys.RETURN)
    time.sleep(10)
    elem8 = driver.find_element_by_xpath("/html/body/div[8]/div[2]/div/div[4]/div/div[1]/div/div/div[3]/div/div/div[7]/div/div/div/div[1]/table/tbody/tr[2]/td[1]/span/input")
    elem8.click()
    time.sleep(10)
    elem9 = driver.find_element_by_xpath("/html/body/div[8]/div[2]/div/div[4]/div/div[1]/div/div/div[3]/div/div/div[5]/div/div[2]/div/table/tbody/tr/td[1]")
    elem9.click()
    time.sleep(10)
    elem10 = driver.find_element_by_xpath("/html/body/div[9]/div/table/tbody/tr[2]/td[2]/div/div/table/tbody/tr[1]/td")
    elem10.click()
    time.sleep(15)
    driver.close()
    time.sleep(10)
except Exception:
    print 'Failed to activate MS-ISAC SNORT rules in the policy'
    driver.close()
    exit()

# Open Firefox using the the specified Firefox profile
driver = webdriver.Firefox(profile)

try:
    # Authenticate to the Defense Center
    Authentication(dcuser, dcpass)
    time.sleep(2)

    # Navigate to the intrusion policy
    driver.get('https://'+ dcip +'/DetectionPolicy/ids.cgi?uuid=' + dcuuid + '#policy')
    time.sleep(10)

    # Commit the policy changes to be pushed to the Source Fire devices
    elem12 = driver.find_element_by_xpath("/html/body/div[8]/div[2]/div/div[4]/div/div[1]/div/div/div[3]/div/div[7]/button[1]")
    elem12.click()
    time.sleep(10)
    elem13 = driver.find_element_by_xpath("/html/body/div[10]/div/table/tbody/tr[2]/td[2]/div/div/div[2]/table/tbody/tr[1]/td/div/textarea")
    elem13.send_keys('New MS-ISAC rules : ' + SNORT_FILE_NAME)
    time.sleep(10)
    elem14 = driver.find_element_by_xpath("/html/body/div[10]/div/table/tbody/tr[2]/td[2]/div/div/div[2]/table/tbody/tr[3]/td/div/button[1]")
    elem14.click()
    time.sleep(60)
    driver.close()
except Exception:
    print 'Failed to commit policy'
    driver.close()
    exit()

print 'Auto Upload successfull of Snort rules : ' + SNORT_FILE_NAME

exit()
