#!/usr/bin/python
#
# KnockKnock by Patrick Wardle is licensed under a Creative Commons Attribution-NonCommercial 4.0 International License.
#

import os
import sys
import json
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse

#project imports
import file
import utils

#global dictionary of VT results
vtResults = {}

#query URL
VT_URL = 'https://www.virustotal.com/partners/sysinternals/file-reports?apikey='

#API key
VT_API_KEY = 'bef728a398d7b666c5fbdc6f64671161284ef49c23e270ac540ada64893b433b'

def processResults(results):

	#item (files) to query
	# ->grab up to 25 before making a query!
	items = []

	#queried startup items
	queriedItems = set()

	#process items, 25 at a time
	for result in results:

		#iterate over each plugin's results
		for startupObj in result['items']:

			#data for item (file)
			itemData = {}

			#only process files
			# ->note, plugins don't be mixed item items, so can bail here
			if not isinstance(startupObj, file.File):

				#stop processing this item group
				break

			#skip items that don't have hashes
			if not startupObj.hash:

				#skip
				continue

			#skip values that already have been queried
			if startupObj.hash in queriedItems:

				#skip
				continue

			#auto start location
			itemData['autostart_location'] = result['name']

			#set item name
			itemData['autostart_entry'] = startupObj.name

			#set item path
			itemData['image_path'] = startupObj.path

			#set hash
			itemData['hash'] = startupObj.hash

			#set creation times
			itemData['creation_datetime'] = os.path.getctime(startupObj.path)

			#add item info to list
			items.append(itemData)

			#save in set of queried items
			queriedItems.add(startupObj.hash)

			#when we've got 25
			# ->query VT
			if 25 == len(items):

				#query
				# ->results stored in global vtResults dictionary
				queryVT(items)

				#reset
				items = []

	#query any remaining items
	if len(items):

		#query
		# ->results stored in global vtResults dictionary
		queryVT(items)

	#(re)iterate over all detected items (results)
	# ->any that were queried add the VT results
	for result in results:

		#iterate over each plugin's results
		for startupObj in result['items']:

			#skip non-item files, or items that weren't queried
			if not isinstance(startupObj, file.File) or \
			   startupObj.hash not in queriedItems:

				#skip
				continue

			#skip items that didn't get a response
			if startupObj.hash not in vtResults:

				#skip
				continue

			#add VT results to item
			startupObj.vtRatio = vtResults[startupObj.hash]

	return vtResults

#query
# ->results stored in global vtResults dictionary
def queryVT(items):

	#headers
	requestHeaders = {}

	#set content type
	requestHeaders['Content-Type'] = 'application/json'

	#set user agent
	requestHeaders['User-Agent'] = 'VirusTotal'

	#wrap
	try:

		#build request
		request = urllib.request.Request(VT_URL+VT_API_KEY, json.dumps(items, indent=4), headers=requestHeaders)

		#make request
		response = urllib.request.urlopen(request)

		#convert response to JSON
		vtResponse = json.loads(response.read())

		#process response
		# ->should be a list of items, within the 'data' key
		if 'data' in vtResponse:

			#process/parse all
			for item in vtResponse['data']:

				#process
				parseResult(item)

	#exceptions
	# ->ignore (likely network related)
	except Exception as e:

		#dbg msg
		utils.logMessage(utils.MODE_ERROR, '\n EXCEPTION, %s() threw: %s' % (sys._getframe().f_code.co_name, e))

		#ignore
		pass

	#bail
	return

#process a single result
#  ->save parse/save info
def parseResult(item):

	#global
	global vtResults

	#extract found flag
	found = item['found']

	#extract hash
	hash = item['hash']

	#when item is found
	# ->save detection ratio
	if found:

		#save detection ratio
		vtResults[hash] = item['detection_ratio']

	#otherwise indicate it wasn't found
	else:

		#not found
		vtResults[hash] = 'not found'

	return








