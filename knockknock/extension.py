__author__ = 'patrick'

import os
import json

#project imports
import utils
import whitelist

class Extension():

	#init method
	# ->init instance variables, hash file, etc
	def __init__(self, extensionInfo):

		#init name w/ None
		self.name = None

		#init path w/ None
		self.path = None

		#init description w/ None
		self.description = None

		#init id w/ None
		self.extensionID = None

		#extact/save id
		if 'id' in extensionInfo:

			#save
			self.extensionID = extensionInfo['id']

		#extact/save name
		if 'name' in extensionInfo:

			#save
			self.name = extensionInfo['name']

		#extact/save path
		if 'path' in extensionInfo:

			#save
			self.path = extensionInfo['path']

		#extact/save description
		if 'description' in extensionInfo:

			#save
			self.description = extensionInfo['description']

		#init whitelist flag
                whitelistedSearch = self.extensionID if self.extensionID != None else self.path
                self.isWhitelisted = (whitelistedSearch in whitelist.whitelistedExtensions)

		return

	#return extension id
	def hash(self):

		#hash
		return self.extensionID

	#return extension's name
	def name(self):

		#name
		return self.name

	#return extension's path
	# ->will be a directory
	def path(self):

		#path
		return self.path

	#for normal output
	def prettyPrint(self):

		#pretty
		return '\n%s \n description: %s\n id: %s\n path: %s\n' % (self.name, self.description, self.extensionID, self.path)

	#for json output
	def __repr__(self):

		#return obj as JSON string
		return json.dumps(self.__dict__, indent=4)
