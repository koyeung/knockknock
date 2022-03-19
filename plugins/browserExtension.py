__author__ = 'patrick w'

'''
browser extensions

    browser extensions can provide a way for code to be executed whenever the browser is launched

    this plugin parses meta data files/directories of Safari, Chrome, and Firefox to find all installed extensions

'''

import os
import glob
import json
import traceback

#project imports
import utils
import extension
import LaunchServices

#plugin framework import
from yapsy.IPlugin import IPlugin

#safari's extensions path
SAFARI_EXTENSION_DIRECTORY = '~/Library/Safari/Extensions/Extensions.plist'

#for output, item name
SAFARI_EXTENSIONS_NAME = 'Safari Browser Extensions'

#for output, description of items
SAFARI_EXTENSIONS_DESCRIPTION = 'Code that is hosted and executed by Apple Safari'

#google chrome's paths to pref files
# ->contains info about installed extensions
CHROME_DIRECTORIES = ['~/Library/Application Support/Google/Chrome/Default/Preferences']

#for output, item name
CHROME_EXTENSIONS_NAME = 'Chrome Browser Extensions'

#for output, description of items
CHROME_EXTENSIONS_DESCRIPTION = 'Code that is hosted and executed by Google Chrome'

#firefox's profile directory
# ->contains each profile's addons
FIREFOX_PROFILE_DIRECTORY = '~/Library/Application Support/Firefox/Profiles'

#for output, item name
FIREFOX_EXTENSIONS_NAME = 'Firefox Browser Extensions'

#for output, description of items
FIREFOX_EXTENSIONS_DESCRIPTION = 'Code that is hosted and executed by Firefox'

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

		#get list of installed browsers
		browsers = self.getInstalledBrowsers()

		#iterate over all browsers
		# ->scan each
		for browser in browsers:

			#scan Safari extensions
			if 'Safari.app' in browser:

				#dbg msg
				utils.logMessage(utils.MODE_INFO, 'safari installed, scanning for extensions')

				#init results
				results.append(self.initResults(SAFARI_EXTENSIONS_NAME, SAFARI_EXTENSIONS_DESCRIPTION))

				#scan
				results[len(results)-1]['items'] = self.scanExtensionsSafari()

			#scan Chrome extensions
			if 'Google Chrome.app' in browser:

				#dbg msg
				utils.logMessage(utils.MODE_INFO, 'chrome installed, scanning for extensions')

				#init results
				results.append(self.initResults(CHROME_EXTENSIONS_NAME, CHROME_EXTENSIONS_DESCRIPTION))

				#scan
				results[len(results)-1]['items'] = self.scanExtensionsChrome()

			#scan Firefox extensions
			if 'Firefox.app' in browser:

				#dbg msg
				utils.logMessage(utils.MODE_INFO, 'firefox installed, scanning for extensions')

				#init results
				results.append(self.initResults(FIREFOX_EXTENSIONS_NAME, FIREFOX_EXTENSIONS_DESCRIPTION))

				#scan
				results[len(results)-1]['items'] = self.scanExtensionsFirefox()

		return results

	#get list of installed browsers
	def getInstalledBrowsers(self):

		#wrap
		try:

			#list of installed browsers
			installedBrowsers = []

			#get list of app IDs that can handle 'https'
			# ->i.e. browsers
			browsersIDs = LaunchServices.LSCopyAllHandlersForURLScheme('https')

			#app IDs to full paths to the apps
			for browserID in browsersIDs:

				#wrap
				try:

					#use LSFindApplicationForInfo to convert ID to app path
					# returns a list, 3rd item an NSURL to the browser
					browserURL = LaunchServices.LSFindApplicationForInfo(LaunchServices.kLSUnknownCreator, browserID, None, None, None)[2]

					#convert the url to a filepath
					installedBrowsers.append(browserURL.path())

				#ignore exceptions
				# ->just want to try next browser
				except Exception as e:

					#ignore
					pass

		#ignore exceptions
		except Exception as e:

			print(e)
			traceback.print_exc()

			#ignore
			pass

		return installedBrowsers

	#scan for Safari extentions
	# ->load plist file, and parse looking for 'Installed Extensions'
	def scanExtensionsSafari(self):

		#results
		results = []

		#get list of all chrome's preferences file
		# ->these contain JSON w/ info about all extensions
		safariExtensionFiles = utils.expandPath(SAFARI_EXTENSION_DIRECTORY)

		#parse each for extensions
		for safariExtensionFile in safariExtensionFiles:

			#wrap
			try:

				#load extension file
				plistData = utils.loadPlist(safariExtensionFile)

				#ensure data looks ok
				if not plistData or 'Installed Extensions' not in plistData:

						#skip/try next
						continue

				#the list of extensions are stored in the 'settings' key
				extensions = plistData['Installed Extensions']

				#scan all extensions
				# ->skip ones that are disabled, white listed, etc
				for currentExtension in extensions:

					#dictionary for extension info
					extensionInfo = {}

					#skip disabled plugins
					if 'Enabled' in currentExtension and not currentExtension['Enabled']:

						#skip
						continue

					#extract path
					if 'Archive File Name' in currentExtension:

						#name
						extensionInfo['path'] = safariExtensionFile + '/' + currentExtension['Archive File Name']

					#extract name
					if 'Bundle Directory Name' in currentExtension:

						#path
						extensionInfo['name'] = currentExtension['Bundle Directory Name']

					#create and append
					results.append(extension.Extension(extensionInfo))

			#ignore exceptions
			except Exception as e:

				#leave in err msg (for now)
				print(e)
				traceback.print_exc()


				#skip/try next
				continue

		return results

	#scan for Chrome extentions
	# ->load JSON file, and parse looking for installed/enabled extensions
	def scanExtensionsChrome(self):

		#results
		results = []

		#get list of all chrome's preferences file
		# ->these contain JSON w/ info about all extensions
		chromePreferences = utils.expandPaths(CHROME_DIRECTORIES)

		#parse each for extensions
		for chromePreferenceFile in chromePreferences:

			#wrap
			try:

				#open preference file and load it
				with open(chromePreferenceFile, 'r') as file:

					#load as JSON
					preferences = json.loads(file.read())
					if not preferences:

						#skip/try next
						continue

				# pref file just has the list of ids,
				# everything else we might want is in
				# os.path.dirname(chromePreferenceFile) + '/Extensions/' + id + version + manifest.json
				# manifest has name, description

				extensions = preferences['extensions']['install_signature']['ids']

				#scan all extensions
				# ->skip ones that are disabled, white listed, etc
				for extensionKey in extensions:

					#dictionary for extension info
					extensionInfo = {}

					#save key
					extensionInfo['id'] = extensionKey
					extensionPath = os.path.dirname(chromePreferenceFile) + '/Extensions/' + extensionInfo['id']

					extdir = os.listdir( extensionPath )
					for verdir in extdir:
							manpath = extensionPath + '/' + verdir + '/manifest.json'

							with open( manpath, 'r' ) as file:
									manifest = json.loads(file.read())
									if not manifest:
											continue;

							extensionInfo['path'] = manpath
							extensionInfo['name'] = manifest['name']
							extensionInfo['description'] = manifest['description']

							#create and append
							results.append(extension.Extension(extensionInfo))

			#ignore exceptions
			except Exception as e:

				#leave in err msg (for now)
				print(e)
				traceback.print_exc()

				#skip/try next
				continue

		return results


	#scan for firefox extensions
	# ->open/parse all 'addons.json' and 'extension.json' files
	def scanExtensionsFirefox(self):

		#results
		results = []

		#dictionary of extension IDs
		# ->needed since they can show up in both addons.json and extensions.json
		extensionIDs = []

		#get list of all firefox's profile directories
		# ->these contain profiles, that in turn, contain a files ('addons.json/extensions.json') about the extensions
		firefoxProfileDirectories = utils.expandPath(FIREFOX_PROFILE_DIRECTORY)

		#iterate over all addons and extensions files in profile directories
		# ->extact all addons and extensions
		for firefoxProfileDirectory in firefoxProfileDirectories:

			#get list of all 'addon.json' files
			firefoxExtensionFiles = glob.glob(firefoxProfileDirectory + '/*.default*/addons.json')

			#and also all 'extensions.json' files
			firefoxExtensionFiles.extend(glob.glob(firefoxProfileDirectory + '/*.default*/extensions.json'))

			#open/parse each addon file
			# ->contains list of addons (extensions)
			for firefoxExtensionFile in firefoxExtensionFiles:

				#wrap
				try:

					#open extension file and load it
					with open(firefoxExtensionFile, 'r') as file:

						#load as JSON
						addons = json.loads(file.read())['addons']
						if not addons:

							#skip/try next
							continue

				#ignore exceptions
				except:

					#skip/try next
					continue

				#extract all addons/extensions
				# ->in both addons and extensions json files, called addons :/
				for addon in addons:

					#dictionary for addon/extension info
					extensionInfo = {}

					#wrap
					try:

						#extract id
						if 'id' in addon:

							#save
							extensionInfo['id'] = addon['id']

						#skip duplicates
						# ->extensions can show up in addons.json and extensions.json
						if addon['id'] in extensionIDs:

							#skip dupe
							continue

						#json in addons.json file is formatted one way
						if 'addons.json' == os.path.split(firefoxExtensionFile)[1]:

							#extract name
							if 'name' in addon:

								#save
								extensionInfo['name'] = addon['name']

							#extract description
							if 'description' in addon:

								#save
								extensionInfo['description'] = addon['description'].replace('\n', ' ')

							#build path
							# ->should be in the extensions/ folder, under <id>.XPI
							path = os.path.split(firefoxExtensionFile)[0] + '/extensions/' + addon['id'] + '.xpi'

							#ignore .xpi's that don't exist
							if not os.path.exists(path):

								#skip
								continue

							#save path
							extensionInfo['path'] = path

						#json in extensions.json file is formatted another way
						else:

							#extract name
							if 'defaultLocale' in addon and 'name' in addon['defaultLocale']:

								#save
								extensionInfo['name'] = addon['defaultLocale']['name']

							#extract description
							if 'defaultLocale' in addon and 'description' in addon['defaultLocale']:

								#save
								extensionInfo['description'] = addon['defaultLocale']['description']

							#build path
							# ->should be a directory in the extensions/ folder, under <id>
							path = os.path.split(firefoxExtensionFile)[0] + '/extensions/' + addon['id']

							#ignore those that don't exist
							if not os.path.exists(path):

								#skip
								continue

							#save path
							extensionInfo['path'] = path

						#save extension id
						# ->used to prevent dupes
						extensionIDs.append(extensionInfo['id'])

						#create and append addon (extension)
						results.append(extension.Extension(extensionInfo))

					#ignore exceptions
					except Exception as e:

						#leave in err msg (for now)
						print(e)
						traceback.print_exc()

						#skip/try next
						continue

		return results









