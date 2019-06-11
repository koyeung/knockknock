import json

#project imports
import file
import command
import extension

#json encoder
class jsonEncoder(json.JSONEncoder):

	#automatically invoked
	# ->allows custom JSON encoding
	def default(self, obj):

		#for file and command objects
		# ->return the objects dictionary
		if isinstance(obj, file.File) or isinstance(obj, command.Command) or isinstance(obj, extension.Extension):

			#object dictionary
			return obj.__dict__

		#other objects
		# ->just super
		else:

			#super
			return super(jsonEncoder, self).default(obj)


#format the results
# ->either just pretty for stdout or as JSON
def formatResults(results, asJSON):

	#results; formatted
	formattedResults = ""

	#cumulative count of all startup objects
	startupObjCount = 0

	#format as JSON
	# ->uses the jsonDecoder class (above) to dump the objects dictionary
	if asJSON:

		#will generate JSON
		formattedResults = json.dumps(results, cls=jsonEncoder, indent=4)

	#pretty print the output for stdout
	else:

		#dbg msg
		formattedResults += 'WHO\'S THERE:\n'

		#iterate over all results
		for result in results:

			#add header (name)
			if result['items']:

				#format name/type of startup item
				formattedResults += '\n[' + result['name'] + ']\n'

			#iterate over each startup object
			for startupObj in result['items']:

				#inc count
				startupObjCount += 1

				#format object
				# ->files and commands both implement prettyPrint()
				formattedResults += startupObj.prettyPrint()

		#none found?
		if not startupObjCount:

			#nothing found
			formattedResults += '-> nobody :)\n'

		#add info about totals
		else:

			#add total
			formattedResults += '\nTOTAL ITEMS FOUND: %d\n' % startupObjCount

	return formattedResults

