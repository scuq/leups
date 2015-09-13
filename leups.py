#!/usr/bin/python
# coding=utf-8
# -*- coding: <utf-8> -*-
# vim: set fileencoding=<utf-8> :

# Copyright (C) 2015    https://github.com/scuq
#                       
# leups
# leups - Least Effort Unattended Patching System
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# http://www.gnu.org/licenses/gpl.txt


scriptname="leups"
version="0.5"
codename="Alaska"

import sys
import os
import re
import shutil
import datetime
import urllib
import time
import logging
import logging.handlers
import csv
import socket
import pexpect
import pxssh
from logging.handlers import SysLogHandler
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(scriptname)
logger.setLevel(logging.INFO)
syslog = SysLogHandler(address='/dev/log')
formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
syslog.setFormatter(formatter)
logger.addHandler(syslog)
from netaddr import EUI
from netaddr import all_matching_cidrs as amc
import netaddr
import daemon
from subprocess import Popen, PIPE, STDOUT
from optparse import OptionParser


def getLatestMacToVlanCsv(cachepath,csvurl):

        urllib.urlretrieve (csvurl, cachepath)

        if os.path.isfile(cachepath):

                return cachepath

        else:

                return "/dev/null"

def is_in_v4subnet(ip, sn):

        res = 0

	try:
        	res = amc(ip, [sn])


	        if len(res) > 0:
       	        	return True

        	else:
                	return False

	except:
		logger.warn("error while trying to match ip in subnet "+str(sys.exc_info()[0])+" "+str(sys.exc_info()[1]))
		return False

def is_valid_ipaddress(ip):

	try:
		socket.inet_aton(ip)
		return True

	except socket.error:
		return False



def is_valid_macaddress(mac):

	try:
		_mac = str(EUI(mac, dialect=netaddr.mac_bare))
		return True
	except netaddr.core.AddrFormatError:
		logger.warn("invalid mac-address: "+str(mac).lower())

	return False


# create example switchport profiles
#
def createExampleProfiles(profiledir):

	if os.path.isdir(profiledir):
	
		profiles = {}

		profile_lan =  "interface $INTERFACE$"+"\n"
		profile_lan += "  desc cl_$DESC$"+"\n"
		profile_lan += "  switchport mode access"+"\n"
		profile_lan += "  switchport nonegotiate"+"\n"
		profile_lan += "  switchport access vlan $VLANID$"+"\n"
		profile_lan += "  no switchport voice vlan"+"\n"
		profile_lan += "  no switchport trunk native vlan"+"\n"
		profile_lan += "  no switchport trunk allowed vlan"+"\n"
		profile_lan += "  no switchport port-security"+"\n"
		profile_lan += "  no macro description"+"\n"
		profile_lan += "  no macro auto processing"+"\n"
		profile_lan += "  speed auto"+"\n"
		profile_lan += "  no vtp"+"\n"
		profile_lan += "  no cdp enable"+"\n"
		profile_lan += "  ip dhcp snooping limit rate 25"+"\n"
		profile_lan += "  storm-control broadcast level 5.00"+"\n"
		profile_lan += "  spanning-tree portfast"+"\n"
		profile_lan += "  load-interval 60"+"\n"
		profile_lan += "  no shutdown"+"\n"+"\n"

                profile_tel =  "interface $INTERFACE$"+"\n"
                profile_tel += "  desc vo_$DESC$"+"\n"
                profile_tel += "  switchport mode access"+"\n"
                profile_tel += "  switchport nonegotiate"+"\n"
                profile_tel += "  switchport access vlan $VLANID$"+"\n"
                profile_tel += "  switchport voice vlan $VOICEVLANID$"+"\n"
                profile_tel += "  no switchport trunk native vlan"+"\n"
                profile_tel += "  no switchport trunk allowed vlan"+"\n"
                profile_tel += "  no switchport port-security"+"\n"
                profile_tel += "  no macro description"+"\n"
                profile_tel += "  no macro auto processing"+"\n"
                profile_tel += "  speed auto"+"\n"
                profile_tel += "  no vtp"+"\n"
                profile_tel += "  no cdp enable"+"\n"
                profile_tel += "  ip dhcp snooping limit rate 30"+"\n"
                profile_tel += "  storm-control broadcast level 5.00"+"\n"
                profile_tel += "  spanning-tree portfast"+"\n"
                profile_tel += "  load-interval 60"+"\n"
                profile_tel += "  no shutdown"+"\n"+"\n"

                profile_ap =  "interface $INTERFACE$"+"\n"
                profile_ap += "  desc an_$DESC$"+"\n"
                profile_ap += "  switchport mode trunk"+"\n"
                profile_ap += "  switchport nonegotiate"+"\n"
		profile_ap += "  no switchport access vlan"+"\n"
		profile_ap += "  no switchport voice vlan"+"\n"
                profile_ap += "  switchport trunk native vlan $VLANID$"+"\n"
                profile_ap += "  no switchport trunk allowed vlan"+"\n"
                profile_ap += "  no switchport port-security"+"\n"
                profile_ap += "  no macro description"+"\n"
                profile_ap += "  no macro auto processing"+"\n"
                profile_ap += "  speed auto"+"\n"
                profile_ap += "  no vtp"+"\n"
                profile_ap += "  no cdp enable"+"\n"
                profile_ap += "  ip dhcp snooping limit rate 30"+"\n"
                profile_ap += "  storm-control broadcast level 5.00"+"\n"
                profile_ap += "  spanning-tree portfast trunk"+"\n"
                profile_ap += "  load-interval 60"+"\n"
                profile_ap += "  no shutdown"+"\n"+"\n"



		profiles["lan"] = profile_lan
		profiles["tel"] = profile_tel
		profiles["ap"] = profile_ap

		for profile in profiles.keys():
                       	pfile = open(profiledir+os.sep+profile, 'w')
                       	pfile.write(profiles[profile].strip())
                        pfile.close()
	


# parse cisco mac notification change trap message
#
def parseNotification(msgs,trapsource):

	_macs = {}
		

	logger.info(str(msgs))
	logger.info(len(msgs)/11)

	# iterate over notifications
	for x in range(0,len(msgs)/11):


		try:
			#  <VLAN> is VLAN number of the VLAN which the MAC address is
			# belonged to and has size of 2 octet.
			_vlan =  int(msgs[x*11+1]+msgs[x*11+2], 16)
			
			# <MAC> is the Layer2 Mac Address and has size of 6 octets.
			_mac = msgs[x*11+3]+msgs[x*11+4]+msgs[x*11+5]+msgs[x*11+6]+msgs[x*11+7]+msgs[x*11+8]

			# <dot1dBasePort> is the value of dot1dBasePort for the
			# interface from which the MAC address is learnt and has size
			# of 2 octets.
			_port =  int(msgs[x*11+9]+msgs[x*11+10], 16)
	
			# add values to a list within a dictionary

			if is_valid_macaddress(_mac):

				_macs[_mac]=[_vlan, _port]
				logger.info("notification received from "+trapsource+" for mac "+str(_mac)+" on port "+str(_port)+" in vlan "+str(_vlan))

			else:
				logger.info("notification received "+trapsource+" for mac "+str(_mac)+" but mac is invalid")
		except:
			logger.warn("error while parsing notification bytes: "+str(msgs))

	return _macs

# write trap to q, simple file in fileystem
# 
def writeFilesystemQ(macs,trapsource,workingdir):

	switchworkingdir = workingdir + os.sep + trapsource

	if not os.path.isdir(switchworkingdir):
		logger.info("creating q directory: "+switchworkingdir)
		os.makedirs(switchworkingdir)
	else:
		for mac in macs.keys():
			if os.path.isfile(switchworkingdir+os.sep+mac+".i"):
				logger.info("mac "+mac+" is already in q for switch "+trapsource)
			else:
				logger.info("adding mac "+mac+" to q for "+trapsource)
				macfile = open(switchworkingdir+os.sep+mac+".i", 'w')
				macfile.write(str(macs[mac][0])+"\n")
				macfile.write(str(macs[mac][1])+"\n")
				macfile.close()

# execute the action
# using ssh because snmp is terrible slow on cisco catalysts
# login with pexpect and do a "show mac address-table"
# if no --dryrun is specified, set the port config
# hardcoded for cisco ios
#
def executeAction(amac2vlan,mac2profile,mac2hostname,switch,dryrun,profiles,scopes,interface_excludes):


	# amac2vlan is a dict which is mapping a mac-address to a vlanid
	# e.g. 04248D187B98 = 1000
#	amac2vlan = {}
#	amac2vlan["84248D187B98"] = 1216

	#mac2profile is a dcit which is mapping a mac-address to a profile
	# e.g. 04248D187B98 = LAN

	scope={}
	scopefound=False

	# find the scope read from the scopes.csv for the current switchip
	for switchsubnet in scopes.keys():
		if is_in_v4subnet(switch,switchsubnet):
			scope = scopes[switchsubnet]
			scopefound=True
			break
	
	
	if scopefound==False:
		logger.error("no scope found for switch ip "+switch+" check your scopes.csv in the config directory")
		return
	else:
		logger.info("scope found for switch ip "+switch+" scope: "+scope["ipv4subnet"])


	if not dryrun:
		logger.info("executeAction called, "+str(len(amac2vlan.keys()))+" pending actions for switch "+switch)
	else:
		logger.info("DRYRUN!! executeAction called, "+str(len(amac2vlan.keys()))+" pending actions for switch "+switch)
	


	try:
		showmactablestr=""
		mactable = {}

		# launch ssh session

		logger.info("starting ssh session to switch: "+switch+" using login: "+scope["sshusername"])
		s = pxssh.pxssh()

		# set ssh username and password
		username = scope["sshusername"]
		password = scope["sshpassword"]

		# set the expected prompt
		s.PROMPT = "[>#]"

		# force password auth
		s.force_password = True

		# login with ssh using the specified values
		s.login(switch, username, password, login_timeout=20,auto_prompt_reset=False)

		# set the terminal length to infinite, this stops commands from paging the output
		# on cisco(like) devices
		#
		s.sendline('terminal length 0\n')

		# execute a show mac address-table, this is done by ssh because it's much faster
		# than snmp
		#
		s.prompt()
		logger.info("executing \"show mac addres-table\"")
		s.sendline('show mac address-table\n')

		# wait for the closing line by the string "Total Mac Addresses"
		s.expect("Total Mac Addresses",timeout=10)

		# fill the shwomactablestr string with the output buffer from the ssh session
		showmactablestr = s.before


		# iterate the output, filtering mac-table by DYNAMIC entries
		#
		exclude_cnt = 0	
		for line in showmactablestr.split("\n"):
			if line.count("DYNAMIC"):
				
				exclude=False

				# replace multiple spaces with one ;
				_line = re.sub(" +",";",line.strip())
				_mac = _line.split(";")[1].replace(".","").upper()
				_port = _line.split(";")[3].strip()

				if is_valid_macaddress(_mac):

					if len(interface_excludes) > 0:
						for excstr in interface_excludes:
							if re.search(excstr,line):
								exclude=True
								exclude_cnt += 1
								logger.debug("line excluded by exclude string:"+excstr+" line: "+line)
						
					if exclude == False:
						mactable[_mac] = _port

		logger.info("number of excluded lines from the show mac address-table command: "+str(exclude_cnt))

		# now we should have a filled mactable dict with mac -> switchport
		# the port is a usable interface name for applying settings later on

		
		# go to conf mode
		if not dryrun:
			logger.info("configure terminal")
			s.sendline('configure terminal\n')
			s.prompt()



		# iterate the mac to vlan table
                for mac in amac2vlan.keys():
			
			# check if we have a profile for this mac address in the csv file
			if mac2profile.keys().count(mac) > 0:
				
				

				logger.info("profile found for mac "+mac+" in csv-file profile-name: "+mac2profile[mac])

				# check if we have a profile loaded for the profile-name got via csv-file
				if profiles.keys().count(mac2profile[mac]) > 0:
					_profilename = mac2profile[mac]
					profile = profiles[_profilename]
				else:
					profile =  "interface $INTERFACE$\n"
					profile += "   desc $DESC$\n"
					profile += "   switchport access vlan $VLANID$\n"
					profile += "   exit\n"
					
			try:
				_interface = mactable[mac]
			except:
				logger.error("error while trying to find interface from \"show mac address-table\" for mac "+mac)
				print mactable
				return 

			if mac2hostname.keys().count(mac) > 0:
				_desc = "leups/"+mac2hostname[mac]
			else:
				_desc = "leups/unknownhostname"


			_vlanid = str(amac2vlan[mac])
			_voicevlanid = scope["voicevlanid"]


			replacedprofile = ""
					
			logger.info("replacing replace-variables with values")
			for line in profile:
				if line.count("$INTERFACE$") > 0:
					replacedprofile += line.replace("$INTERFACE$",_interface)
					continue
				if line.count("$VOICEVLANID$") > 0:
					replacedprofile += line.replace("$VOICEVLANID$",_voicevlanid)
					continue
				if line.count("$VLANID$") > 0:
					replacedprofile += line.replace("$VLANID$",_vlanid)
					continue
				if line.count("$DESC$") > 0:
					replacedprofile += line.replace("$DESC$",_desc)
					continue

				replacedprofile += line
				

					
			for line in replacedprofile.split("\n"):

				logger.info(line)
				if not dryrun:
					s.sendline(line+"\n")
					s.prompt()

			if not dryrun:
				s.sendline("  exit\n")
				s.prompt()

		if not dryrun:
                        s.sendline('end\n')
                        s.prompt()



	

		s.logout()
	except:
		logger.error("error while executing ssh action on switch "+switch+" "+str(sys.exc_info()[0])+" "+str(sys.exc_info()[1]))


def loadProfiles(profiledir):

	profiles = {}

	# get a list of profile files 
	for root, dirs, files in os.walk(profiledir):
		for pfile in files:
			f = open(profiledir+os.sep+pfile, 'r')
			profiles[pfile.upper()] = f.readlines()
			f.close()

	logger.info("number of switchport profiles loaded: "+str(len(profiles.keys())))

	return profiles

def loadExcludes(excludesfile):

	excludes=[]

	excludelines=""

        try:
                f = open(excludesfile, 'r')
                # ignore first line - header
                f.readline()
                excludelines = f.readlines()
                f.close()
        except:
                logger.error("error while reading interface.exclude file.")
                sys.exit(1)

        for line in excludelines:
		if not line.strip().startswith("#"):
			excludes.append(line.strip())
		
	logger.info("number of interface exclude expressions loaded: "+str(len(excludes)))

	return excludes

def loadAutodryScopes(scopecsvfile):

        scopes={}

        # col0 = switch-mgmt-subnet
        # col1 = dryrun or not

	# dryrun will always be used unless
	# col1 is NO-DRYRUN

        scopecsvlines=""

        try:
                f = open(scopecsvfile, 'r')
                # ignore first line - header
                f.readline()
                scopecsvlines = f.readlines()
                f.close()
        except:
                logger.error("error while reading "+scopecsvfile+" file.")
                sys.exit(1)

        for line in scopecsvlines:
                scope={}
                if line.split(";") >= 2:
                        scope["locationid"]  = line.split(";")[0]
			scope["ipv4subnet"]  = line.split(";")[1] 
			_dryrunornot = line.split(";")[2]
			if _dryrunornot == "NO-DRYRUN":
	                        scope["dryrun"]  = False
			else:
				scope["dryrun"]  = True

                        scopes[scope["ipv4subnet"]] = scope

        logger.info("number of autodry scopes loaded: "+str(len(scopes.keys())))

        return scopes

def loadScopes(scopecsvfile):

	scopes={}

	# col0 = switch-mgmt-subnet
	# col1 = ssh-username
	# col2 = ssh-password
	# col3 = voicevlanid

	scopecsvlines=""
	
	try:
	        f = open(scopecsvfile, 'r')
		# ignore first line - header
		f.readline()
       		scopecsvlines = f.readlines()
        	f.close()
	except:
		logger.error("error while reading scope.csv file.")
		sys.exit(1)

	for line in scopecsvlines:
		scope={}
		if line.split(";") >= 5:
			scope["locationid"]  = line.split(";")[0] 
			scope["ipv4subnet"]  = line.split(";")[1] 
			scope["sshusername"]  = line.split(";")[2] 
			scope["sshpassword"]  = line.split(";")[3] 
			scope["voicevlanid"]  = line.split(";")[4] 

			scopes[scope["ipv4subnet"]] = scope

	logger.info("number of scopes loaded: "+str(len(scopes.keys())))

	return scopes

# start the worker loop
# keeps looking for new files 
# created by snmp traps with snmptt
# and leups in --store mode
#
def worker(workingdir,dryrun,profiles,scopes,interface_excludes,locationawareness,ignorelocationid,autodryrun, autodryscopes):


	# init empty dict for mac -> vlan from csv
	mac2vlan = {}

	# init empty dict for mac -> hostname from csv
	mac2hostname = {}

	# init empty dict for mac -> profile from csv
	mac2profile = {}

        # init empty dict for mac -> locationid from csv
        mac2locationid = {}

	

	error=False


	if os.path.isfile(workingdir+os.sep+"mac2vlan.csv"):



		# load csv file
		try:
			with open(workingdir+os.sep+'mac2vlan.csv', 'rb') as csvfile:
				m2vcsvreader = csv.reader(csvfile,delimiter=";",quotechar='"')
				for row in m2vcsvreader:
					try:
						mac2hostname[str(row[0]).upper()] = row[3]
					except: 
						mac2hostname="unknown-host"
					try:
						mac2profile[str(row[0]).upper()] = row[8]
					except: 
						mac2profile="<NONE>"
					try:
						mac2vlan[str(row[0]).upper()] = int(row[4])
					except:
						mac2vlan[str(row[0]).upper()] = 0
                                        try:
                                                mac2locationid[str(row[0]).upper()] = int(row[1])
                                        except:
                                                mac2locationid[str(row[0]).upper()] = 1
		except:
			logger.warn("error on parsing mac2vlan.csv file"+" "+str(sys.exc_info()[0])+" "+str(sys.exc_info()[1]))
			error=True
			

		# if load is ok, continue
		if not error:



			# get a list of subdirs of the workingdir 
			# the subdir name have to be a valid ipv4 address
			for root, dirs, files in os.walk(workingdir):
	
				# iterate subdirs (switch ips)
				for switchipdir in dirs:

					# init empty dict for mac -> vlan for mac-addresses which should trigger a action
					amac2vlan={}

					# init empty dict for mac -> vlan from q files
					qmac2vlan = {}

					# init empty dict for mac -> port from q files
					qmac2port = {}

					# check if dir is a valid ip address
					if is_valid_ipaddress(switchipdir):

						logger.info("q directory for switch "+switchipdir+" found.")

						# get a list of files of the switch directory
						for swroot, swdirs, swfiles in os.walk(workingdir+os.sep+switchipdir):

							# iterate files in subdir/switch dir, check if the file ends with an ".i" 
							# leups creates .i files while receiving traps from snmptt
							for macfile in swfiles:
								if macfile.endswith(".i"):
									logger.debug("processing q item (mac-address): "+macfile)


									# read the file, 1st line contains the vlan id
									# the switch learned the mac address
									# second line contains the port where the mac was
									# learned
									

									try:
										mqfile = open(swroot+os.sep+macfile)
										_lines = mqfile.readlines()
										mqfile.close()
										_mac = str(macfile.replace(".i","")).upper()
										_vlan = int(_lines[0].replace("\n",""))
										_port = int(_lines[1].replace("\n",""))
										qmac2vlan[_mac]=_vlan	
										qmac2port[_mac]=_port	
									except:
										logger.warn("error while reading or parsing q file: "+swroot+os.sep+macfile+" "+str(sys.exc_info()[0])+" "+str(sys.exc_info()[1]))
										
										pass

								#if not dryrun:
								logger.info("removing file from q "+workingdir+os.sep+switchipdir+os.sep+macfile)
								os.remove(workingdir+os.sep+switchipdir+os.sep+macfile)

									
			
		
					# let's check what's to do

					if not error:

						if locationawareness:
							logger.info("location awarness is active")

						for mac in qmac2vlan.keys():

							if locationawareness:
								specific_location_found = False
								location_found = False
	

							try:
								if not qmac2vlan[mac] == mac2vlan[mac]:

									# if location awareness is enabled, try to match the locationid from the scopes file
									# column number 1 to the locationid of the mac2vlan.csv file, if the mac is found and the location
									# ids are matching, the mac will be added to the action-mac-dict, if no match is found the default
									# "global" location id "1" will be used to match a location
									if locationawareness:



										if mac2vlan[mac] == 0:
											logger.debug("action maybe needed, for mac "+mac+" ("+mac2hostname[mac]+") switch "+switchipdir+" but we have no valid vlan in the csv, switch reported vlan "+str(qmac2vlan[mac])+" csv contains vlan "+str(mac2vlan[mac]))
										else:

											# find the scope of the switch in the scopes dict
											scope={}
											scopefound=False

											# find the scope read from the scopes.csv for the current switchip
											for switchsubnet in scopes.keys():
												if is_in_v4subnet(switchipdir,switchsubnet):
													scope = scopes[switchsubnet]
													scopefound=True
													break


                                                                                        # find the scope of the switch in the autodry scopes dict
                                                                                        autodryscope={}
                                                                                        autodryscopefound=False

                                                                                        # find the scope read from the scopes.csv for the current switchip
                                                                                        for switchsubnet in autodryscopes.keys():
                                                                                                if is_in_v4subnet(switchipdir,switchsubnet):
                                                                                                        autodryscope = autodryscopes[switchsubnet]
                                                                                                        autodryscopefound=True
                                                                                                        break

											if autodryrun:
												logger.info("autodryrun active")
												dryrun = False
												if autodryscopefound:
													if autodryscope["dryrun"] == True:
														dryrun = True
														logger.info("autodry run has set switch "+switchipdir+" to DRYRUN.")
													else:
														dryrun = False
														logger.info("autodry run has set switch "+switchipdir+" to ENFORCING.")


											# check if the locationid of the switch, found via scopes
											# matches the locationid of the mac in the mac2vlan file
											if int(scope["locationid"]) == int(mac2locationid[mac]):
												if not int(ignorelocationid) == mac2locationid[mac]:
													amac2vlan[mac]=mac2vlan[mac]
													logger.info("action needed, for mac "+mac+" switch "+switchipdir+" reported vlan "+str(qmac2vlan[mac])+" csv contains vlan "+str(mac2vlan[mac])+" for locationid: "+str(scopes["locationid"]))
													specific_location_found = True
												else:
													logger.info("action needed, for mac "+mac+" switch "+switchipdir+" reported vlan "+str(qmac2vlan[mac])+" csv contains vlan "+str(mac2vlan[mac])+" for locationid: "+str(scopes["locationid"])+" but locationid is set to ignore")
			

							
											# if no specific location was found via the scope to mac location id match above
											# check if the mac has location id "1", the global location id
											if specific_location_found == False and mac2locationid[mac] == 1:
                                                                                                if not int(ignorelocationid) == mac2locationid[mac]:
													amac2vlan[mac]=mac2vlan[mac]
													location_found = True
													logger.info("action needed, for mac "+mac+" switch "+switchipdir+" reported vlan "+str(qmac2vlan[mac])+" csv contains vlan "+str(mac2vlan[mac])+" for global locationid: 1")
												else:
													logger.info("action needed, for mac "+mac+" switch "+switchipdir+" reported vlan "+str(qmac2vlan[mac])+" csv contains vlan "+str(mac2vlan[mac])+" for global locationid: 1, but locationid is set to ignore")
	



											if location_found == False:
													logger.info("action maybe needed, for mac "+mac+" switch "+switchipdir+" reported vlan "+str(qmac2vlan[mac])+" csv contains vlan "+str(mac2vlan[mac])+", but no matching locationid found, locationid of csv: "+str(mac2locationid[mac])+" locationid of switch: "+str(scope["locationid"]))
											

									else:


										if mac2vlan[mac] == 0:
											logger.debug("action maybe needed, for mac "+mac+" ("+mac2hostname[mac]+") switch "+switchipdir+" but we have no valid vlan in the csv, switch reported vlan "+str(qmac2vlan[mac])+" csv contains vlan "+str(mac2vlan[mac]))
										else:
											amac2vlan[mac]=mac2vlan[mac]
											logger.info("action needed, for mac "+mac+" switch "+switchipdir+" reported vlan "+str(qmac2vlan[mac])+" csv contains vlan "+str(mac2vlan[mac]))

								else:
									logger.debug("no action needed, switch reported vlan "+str(qmac2vlan[mac])+" csv contains vlan "+str(mac2vlan[mac]))

							except KeyError:

									logger.debug("mac-address ("+mac+") not found in csv file, switch reported vlan "+str(qmac2vlan[mac])+" on port "+str(qmac2port[mac]))
									pass
				 
					if not error:





						if len(amac2vlan.keys()) > 0:
							executeAction(amac2vlan,mac2profile,mac2hostname,switchipdir,dryrun,profiles,scopes,interface_excludes)
						else:
							logger.info("no action needed on switch: "+switchipdir)


	else:
		logger.warn("no mac2vlan.csv file found, cannot lookup vlan for mac-addresses.")


	return


def main():

        parser = OptionParser()
        parser.add_option("-t", "--trapsource", dest="trapsource", help="")
        parser.add_option("-m", "--macchangedmsg", dest="machangedmsg", help="")
        parser.add_option("-s", "--store", action="store_true", dest="store", default=False, help="store mode, mode for use with snmptt")
        parser.add_option("-w", "--worker", action="store_true", dest="worker", default=False, help="worker mode, reads the q and execute actions")
        parser.add_option("-l", "--locationawareness", action="store_true", dest="locationawareness", default=False, help="enable location awareness")
        parser.add_option("-i", "--ignorelocation", dest="ignorelocationid", help="ignore the following locationid")
        parser.add_option("-r", "--dryrun", action="store_true", dest="dryrun", default=False, help="worker mode, dry run, don't configure anything")
        parser.add_option("-a", "--autodry", action="store_true", dest="autodryrun", default=False, help="worker mode, auto switch dryrun on or off by dryrun.csv only allowed with --dryrun and --locationawareness")
        parser.add_option("-u", "--updater", action="store_true", dest="updater", default=False, help="updater mode, get new cmdb cache database")
	parser.add_option("-d", "--daemon", action="store_true", dest="daemon", default=False, help="start !!worker!! mode as daemon")
	parser.add_option("", "--debug", action="store_true", dest="debug", default=False, help="enable debug logging")
        parser.add_option("", "--csv-url", dest="csvurl", help="url where mac -> vlan, mac -> switchport profile csv file could be fetched, use with --updater")
        parser.add_option("-v", "--version", action="store_true", dest="showversion", default=False, help="display version information")
        parser.add_option("", "--show-csv-format", action="store_true", dest="showcsv", default=False, help="display the csv format definition")
        parser.add_option("", "--show-snmptt-example", action="store_true", dest="showsnmptt", default=False, help="display an example config for snmptt")
        parser.add_option("", "--show-catalyst-example", action="store_true", dest="showcatalyst", default=False, help="display an example config for a cisco catalyst 2960")
        parser.add_option("", "--show-profile-replacementvars", action="store_true", dest="showprofilereplacementvars", default=False, help="show profile replacement variables")
        parser.add_option("", "--create-example-profile", action="store_true", dest="createexampleprofiles", default=False, help="create example switchport profiles in /var/lib/leups/_profiles")
        (options, args) = parser.parse_args()


	workingdir = "/var/lib/leups"
	configdir = "/etc/leups"
	profiledir = configdir+os.sep+"profiles"
	scopefile = "/dev/null"


	if options.debug:
		logger.setLevel(logging.DEBUG)

	if options.autodryrun:
		if not options.dryrun or not options.autodryrun or not options.locationawareness:
			logger.error("--autodry is only valid with --dryrun and --locationawareness")
			sys.exit(1)

	if options.showprofilereplacementvars:
		print "Profile Replacment Variables:"
		print
		print "$INTERFACE$"
		print "$DESC$"
		print "$VLANID$"
		print "$VOICEVLANID$"
		print
		sys.exit(0)


        if options.showcatalyst:
                print "Example Cisco Switch Trap Config:"
                print
		print "conf t"
		print "   snmp-server enable traps mac-notification change"
		print "   mac address-table notification change interval 10"
		print "   mac address-table notification change"
		print
		print "   snmp-server host 10.1.1.1 version 2c swipro"	
		print 
		print "int range g1/0/1"
		print "  snmp trap mac-notification change added"
		print "  exit"
                print
		sys.exit(0)

	if options.showversion:
		print "Scriptname: "+scriptname
		print "Version: "+version
		print "Codename: "+codename
		sys.exit(0)

        if options.showcsv:
		print '"<MAC-ADDRESS>";<UNUSED>;<UNUSED>;"<HOSTNAME>";"<VLANID>";<UNUSED>;<UNUSED>;<UNUSED>;"<PROFILE>";'
		print
		print "example:"
		print '00000000000a;;;"client-host1";"1000";"";"";"";"cl";'
                sys.exit(0)	

	# print example config for snmptt 
	# cisco notification mib
	if options.showsnmptt:
		print '#MIB: CISCO-MAC-NOTIFICATION-MIB'
		print 'EVENT cmnMacChangedNotification .1.3.6.1.4.1.9.9.215.2.0.1 "Status Events" Normal'
		print 'FORMAT This notification is generated when there is enough MAC $*'
		print 'EXEC /unet/scripts/leups.py --store --trapsource "$aR" --macchangedmsg "$*"'
		print 'SDESC'
		print 'EDESC'
                sys.exit(0)	


	if options.createexampleprofiles:

		if not os.path.isdir(profiledir):
			try:
				logger.info("creating profile directory: "+profiledir)
				os.makedirs(profiledir)
			

			except:
				logger.error("error while creating profile directory: "+profiledir)
				sys.exit(1)

		createExampleProfiles(profiledir)
		sys.exit(0)
	

	try:
		if not os.path.isdir(workingdir):
			logger.info("creating working directory: "+workingdir)
			os.makedirs(workingdir)
	except:
		logger.error("error while creating working directory: "+workingdir)
		sys.exit(1)

	if not options.store and not options.worker and not options.updater:
		logger.info("please specify a mode, store, worker or updater")
		sys.exit(1)

	

	# check if script is stared in store mode (trap receive mode)
	if options.store:
		logger.info("started in store mode (trap receive mode)")

		if options.trapsource:
			trapsource=options.trapsource
		else:
			logger.error("trapsource not given --trapsource")
			sys.exit(1)

	
       		if options.machangedmsg:
               		machangedmsg=str(options.machangedmsg)
        	else:
                	logger.error("machangedmsg not given --machangedmsg")
                	sys.exit(1)

		# remove 2x space
		machangedmsg  = re.sub("\s\s+", " ", machangedmsg) 

		machangedmsgs = machangedmsg.split(" ")

		# one MacChangedMsg consists of 11 octets in the format <operation><VLAN><MAC><dot1dBasePort>


		

		_macs = {}

		# check the msg length
		if (len(machangedmsgs)/11) > 0:
			logger.info("mac change notification received, mac count: "+str(len(machangedmsgs)/11)) 

        		scopefound=False

			
                	if not os.path.isfile(configdir+os.sep+"scopes.csv"):
                        	logger.error("scopes.csv doesn't exist ("+configdir+os.sep+"scopes.csv"")")
                        	sys.exit(1)

                       	scopefile=configdir+os.sep+"scopes.csv"
       	        	scopes={}

	                scopes = loadScopes(configdir+os.sep+"scopes.csv")

		        # find the scope read from the scopes.csv for the current switchip
        		for switchsubnet in scopes.keys():
                		if is_in_v4subnet(trapsource,switchsubnet):
                        		scope = scopes[switchsubnet]
                        		scopefound=True
                        		break

			if scopefound == False:
				logger.warn("switch "+trapsource+" not found in scope.csv, ignoring trap")
			else:
				logger.info("switch "+trapsource+" found in scope.csv")

				_macs = parseNotification(machangedmsgs,trapsource)

		else: 
			logger.info("mac change notification received, but no useable data found.") 


		writeFilesystemQ(_macs,trapsource,workingdir)
			

			

	# check if script is stared in worker mode 
	if options.worker:




		if not os.path.exists(configdir):
			logger.error("config directory ("+configdir+") doesn't exist")
			sys.exit(1)

		if not os.path.isfile(configdir+os.sep+"scopes.csv"):
			logger.error("scopes.csv doesn't exist ("+configdir+os.sep+"scopes.csv"")")
			sys.exit(1)
		else:
			scopefile=configdir+os.sep+"scopes.csv"

                if not os.path.isfile(configdir+os.sep+"interface.exclude"):
                        logger.error("interface.exclude doesn't exist ("+configdir+os.sep+"interface.exclude"")")
                        sys.exit(1)


		profiles={}

		profiles = loadProfiles(profiledir)

		scopes={}

		scopes = loadScopes(configdir+os.sep+"scopes.csv")

		autodryscopes={}

		if options.autodryrun:
			autodryscopes = loadAutodryScopes(configdir+os.sep+"dryrun.csv")
		
		interface_excludes=[]

		interface_excludes= loadExcludes(configdir+os.sep+"interface.exclude")


		if options.daemon:

			logger.info("started in worker daemon mode")
			with daemon.DaemonContext():
				worker(workingdir,options.dryrun,profiles,scopes,interface_excludes,options.locationawareness,options.ignorelocationid,options.autodryrun,autodryscopes)
				time.sleep(25)

		else:

			logger.info("started in worker fg mode")
			while True:
				worker(workingdir,options.dryrun,profiles,scopes,interface_excludes,options.locationawareness,options.ignorelocationid,options.autodryrun,autodryscopes)
				time.sleep(25)

			



        # check if script is stared in worker mode 
        if options.updater:

		if not options.csvurl:
			logger.error("missing arg --csv-url")
			sys.exit(1)

                logger.info("started in updater mode. fetching mac2vlan csv.")

		
		cf = getLatestMacToVlanCsv(workingdir+os.sep+"mac2vlan.csv",options.csvurl)

		logger.info("mac2vlan csv written to: "+cf)
	

if __name__ == '__main__':
        main()
                                                         
