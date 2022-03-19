__author__ = 'patrick w'

'''
dylibs (loaded via DYLD_INSERT_LIBRARIES)

    the DYLD_INSERT_LIBRARIES environment variable can be set to the path of a dynamic library (.dylib)

    for local settings, the plugin scans plists of launch daemons and agents, and all installed apps to determine if any dylibs are set
    for global settings, the plugin...

'''

# for launch agents
# edit com.blah.blah.plist
# <key>EnvironmentVariables</key>
#   <dict>
#   <key>DYLD_INSERT_LIBRARIES</key>
#   <string>/path/to/dylib</string>
#  </dict>
#
# for apps
# <key>LSEnvironment</key>
#   <dict>
# 	  <key>DYLD_INSERT_LIBRARIES</key>
#	  <string>/path/to/dylib</string>
#	  </dict>
# /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -v -f /Applications/ApplicationName.app

import os
import glob

#project imports
import file
import utils

#plugin framework import
from yapsy.IPlugin import IPlugin

#directories for launch daemons and agents
LAUNCH_ITEMS_DIRECTORIES = ['/System/Library/LaunchDaemons/', '/Library/LaunchDaemons/', '/System/Library/LaunchAgents/', '/Library/LaunchAgents/', '~/Library/LaunchAgents/']

#key for launch items
LAUNCH_ITEM_DYLD_KEY = 'EnvironmentVariables'

#key for applications
APPLICATION_DYLD_KEY = 'LSEnvironment'

#for output, item name
INSERTED_DYNAMIC_LIBRARIES_NAME = '(inserted) Dynamic Libraries'

#for output, description of items
INSERTED_DYNAMIC_LIBRARIES_DESCRIPTION = 'Dynamic Libraries that are set to be injected via DYLD_INSERT_LIBRARIES'

class scan(IPlugin):

	#init results dictionary
	# ->item name, description, and list
	def initResults(self, name, description):

		#results dictionary
		return {'name': name, 'description': description, 'items': []}

	#invoked by core
	def scan(self):

		#results
		results = []

		#dbg msg
		utils.logMessage(utils.MODE_INFO, 'running scan')

		#init results
		results = self.initResults(INSERTED_DYNAMIC_LIBRARIES_NAME, INSERTED_DYNAMIC_LIBRARIES_DESCRIPTION)

		#scan launch items for inserted dylibs
		launchItems = scanLaunchItems(LAUNCH_ITEMS_DIRECTORIES)
		if launchItems:

			#save
			results['items'].extend(launchItems)

		#scan all installed applications for inserted dylibs
		applications = scanApplications()
		if applications:

			#save
			results['items'].extend(applications)

		return results

#scan launch agents or daemons
# for each directory, load all plist's and look for 'DYLD_INSERT_LIBRARIES' key within a 'EnvironmentVariables'
def scanLaunchItems(directories):

	#launch items
	launchItems = []

	#expand directories
	# ->ensures '~'s are expanded to all user's
	directories = utils.expandPaths(directories)

	#get all files (plists) in launch daemon/agent directories
	for directory in directories:

		#dbg msg
		utils.logMessage(utils.MODE_INFO, 'scanning %s' % directory)

		#get launch daemon/agent plist
		launchItems.extend(glob.glob(directory + '*'))

	#check all plists for DYLD_INSERT_LIBRARIES
	# ->for each found, creates file object
	return scanPlists(launchItems, LAUNCH_ITEM_DYLD_KEY)

#scan all installed applications
# for each directory, load all apps' Info.plist and look for 'DYLD_INSERT_LIBRARIES' key within a 'LSEnvironment'
def scanApplications():

	#app plists
	appPlists = []

	#dbg msg
	utils.logMessage(utils.MODE_INFO, 'generating list of all installed apps (this may take some time)')

	#get all installed apps
	installedApps = utils.getInstalledApps()

	#sanity check
	# ->using system_profiler (to get installed apps) can timeout/throw exception, etc
	if not installedApps:

		#bail
		return None

	#now, get Info.plist for each app
	for app in installedApps:

		#skip apps that don't have a path
		if not 'path' in app:

			#skip
			continue

		#get/load app's Info.plist
		plist = utils.loadInfoPlist(app['path'])

		#skip apps that don't have Info.plist
		if not plist:

			#skip
			continue

		#save plist for processing
		appPlists.append(plist)

	#check all plists for DYLD_INSERT_LIBRARIES
	# ->for each found, creates file object
	return scanPlists(appPlists, APPLICATION_DYLD_KEY, isLoaded=True)


#scan a list of plist
# ->check for 'DYLD_INSERT_LIBRARIES' in plist, and if found, create file obj/result
def scanPlists(plists, key, isLoaded=False):

	#results
	results = []

	#sanity check
	if not plists:

		#bail
		return None

	#iterate over all plist
	# ->check for 'DYLD_INSERT_LIBRARIES' enviroment variable
	for plist in plists:

		#wrap
		try:

			#load contents of plist if needed
			if not isLoaded:

				#save path
				plistPath = plist

				#load it and check
				loadedPlist = utils.loadPlist(plist)
				if not loadedPlist:

					#skip
					continue

			#otherwise it's already loaded
			# ->use as is
			else:

				#set
				loadedPlist = plist

				#get path
				plistPath = utils.getPathFromPlist(loadedPlist)

			#check for env key
			# -> will be either 'EnvironmentVariables' or 'LSEnvironment' depending if launch item or app
			if key in loadedPlist:

				#check for/save DYLD_INSERT_LIBRARIES
				if 'DYLD_INSERT_LIBRARIES' in loadedPlist[key]:

					#create file obj and append to results
					results.append(file.File(loadedPlist[key]['DYLD_INSERT_LIBRARIES'], plistPath))

				#check for/save __XPC_DYLD_INSERT_LIBRARIES
				if '__XPC_DYLD_INSERT_LIBRARIES' in loadedPlist[key]:

					#create file obj and append to results
					results.append(file.File(loadedPlist[key]['__XPC_DYLD_INSERT_LIBRARIES'], plistPath))

		#ignore exceptions
		except Exception as e:

			#ignore
			pass

	return  results










