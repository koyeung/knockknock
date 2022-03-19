import json

#project imports
import utils

#whitelisted files
WHITE_LISTED_FILES = 'whitelists/whitelistedFiles.json'

#whitelisted commands
WHITE_LISTED_COMMANDS = 'whitelists/whitelistedCommands.json'

#whitelisted browser extensions
WHITE_LISTED_EXTENSIONS = 'whitelists/whitelistedExtensions.json'

#global white list
# ->hashes/info of known good files
whitelistedFiles = []

#global white list
# ->commands
whitelistedCommands = []

#global white list
# ->browser extensions
whitelistedExtensions = []

#todo make this a class with iVars instead of globals

#load whitelists
def loadWhitelists():

	#global files
	global whitelistedFiles

	#global commands
	global whitelistedCommands

	#global
	global whitelistedExtensions

	#open/load whitelisted files
	with open(utils.getKKDirectory() + WHITE_LISTED_FILES) as file:

		#load
		whitelistedFiles = json.load(file)

	#open/load whitelisted commands
	with open(utils.getKKDirectory() + WHITE_LISTED_COMMANDS) as file:

		#load
		# ->note, commands are in 'commands' array
		whitelistedCommands = json.load(file)['commands']

	#open/load whitelisted commands
	with open(utils.getKKDirectory() + WHITE_LISTED_EXTENSIONS) as file:

		#load
		# ->note, commands are in 'commands' array
		whitelistedExtensions = json.load(file)