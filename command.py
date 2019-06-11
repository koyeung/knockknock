__author__ = 'patrick'

import json

#project imports
import whitelist

class Command():

	#init method
	# ->save command and set white list flag
	def __init__(self, command, file=None):

		#save command
		self.command = command

		#save file
		self.file = file

		#init whitelist flag
		# ->simply set to True if command is list of whitelisted commands
		self.isWhitelisted = (self.command in whitelist.whitelistedCommands)

		return

	#for json output
	def __repr__(self):

		#return obj as JSON string
		return json.dumps(self.__dict__, indent=4)

	#for normal output
	def prettyPrint(self):

		#pretty-printed string
		string = ''

		#when cmd has file
		if self.file:

			#init
			string = '\n%s\n file: %s\n' % (self.command, self.file)

		#no file
		else:

			#init
			string = '\n%s\n' % (self.command)


		return string
