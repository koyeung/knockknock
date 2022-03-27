# KnockKnock Plugin Writing Guide

There are many methods of persistence on OS X - and new ones are sure to be found.
As such, KnockKnock was designed to use a plugin-based architecture,
where each plugin can scan for a particular persistence technique.
When new persistence techniques are discovered, KnockKnock can easily be extended with new plugins.
Luckily, writing a plugin for KnockKnock is quite simply, as the core performs most of the work.

KnockKnock uses the open sourced python plugin system Yapsy (http://yapsy.sourceforge.net/).
Yapsy is a simple, yet elegant plugin system which is very thoroughly documented.

Writing a plugin for KnockKnock requires two files;
a configuration file containing meta data required by Yapsy (to find/load the plugin)
and a plugin python file (containing the plugin’s code).
Both these files are described below, in quite some detail.

In order for KnockKnock (via Yapsy) to find and load the plugin,
each plugin must contain a configuration file.
This file must have the same name as the plugin file, but have a .yapsy-plugin extension.
There are several sections and fields that are required to be in this file:

```
[Core]
Name = <descriptive name of the plugin>
Module = <name of the plugin, *must* match the name of the plugin file>

[Documentation]
Author = <name of the author>
Version = <version of the plugin>
Description = <description of what the plugin does>
```

Everything in this file is fairly self-explanatory. 
However it is worth reiterating that the value of ‘Module’ field must match the name of the 
plugin’s python file (minus the .py file extension). 
For example, if a plugin is implemented within some_plugin.py, 
the ‘Module’ field would contain ‘some_plugin’ as its value.

The actual code for the plugin must perform several actions in order to conform as an invokable
plugin. However, these are fairly straightforward, and can be easily templatized. 
First the plugin should import the plugin interface definition via:

```python
from knockknock.plugin_base import KnockKnockPlugin
```

Following this, the plugin should create a scan class, and implement a `scan()` method:

```python
class Scan(KnockKnockPlugin):

	def scan(self):
		# plugin logic
```

The scan class method is automatically invoked by the KnockKnock core when the plugin is loaded and
executed. As such, the plugin’s logic should begin here.
The plugin, which will be enumerating a specific persistence class, is free to gather information
in any way it sees fit. This information is then returned to the KnockKnock core by returning a 
dictionary from the scan() method. 

In order for the results to be ‘readable’ by the core,
the `scan()` function must return a dictionary that contains several required key/value pairs.
These include:

‘name’ : the name persistence class 
‘description’ : description of the persistence class
‘items’ :	list of persistence objects detected by the plugin

While the ‘name’ and ‘description’ members of the result dictionary are mostly for informational
purposes and can contain anything the plugin author decides, the ‘items’ list requires more
discussion. 

KnockKnock recognized two types of persistence items; files and commands.
Files include binaries, applications, etc, while commands are persistent instructions that are
executed each time the computer is rebooted. KnockKnock has object representations for both types
of persistence objects (files and commands). This means, adding a persistence item into the ‘items’
list is a simple as instantiating the appropriate object. The command object initializer takes a
single argument; a string containing the command. The file object initializer takes up to two
commands; a string containing the path to a persistent file (or its bundle), and optionally,
a plist associated with the file. The following examples illustrate both the initialization of
a command and file object:

```python
#add command into ‘items’ list
# note: extracted command is a string containing some persistent command
results['items'].append(command.Command(extractedCommand))

#add file (in this case a kext bundle) into ‘items’ list
results['items'].append(file.File(kextBundle))
```

# example
The following example illustrates a KnockKnock plugin which can enumerate all installed
kernel extensions:

First, the plugin config/meta data file

```
#file name: kext.yapsy-plugin
[Core]
Name = Kext Scanner
Module = kext

[Documentation]
Author = Patrick W
Version = 1.0
Description = Plugin that scans for installed kernel extensions
```

Then the plugin code

```python
#file name: kext.py

import glob

from knockknock import file
from knockknock.plugin_base import KnockKnockPlugin

#directories where kexts live
KEXT_DIRECTORIES = ['/System/Library/Extensions/', '/Library/Extensions/']


class Scan(KnockKnockPlugin):
 """Plugin Class."""

 def scan(self):
	"""Scan action."""
	#kexts
	kexts = []
	
	#init results dictionary
	results = self.init_results('Kernel Extensions', 'KEXT_DESCRIPTION')

	#get all files in kext directories
	for kextDir in KEXT_DIRECTORIES:

		#get kexts
		kexts.extend(glob.glob(kextDir + '*'))

		#process
		# ->gets kext's binary, then create file object and add to results
		for kextBundle in kexts:

			#skip kext bundles that don't have kext's
			if not utils.getBinaryFromBundle(kextBundle):

				#next!
				continue

			#create and append
			# ->pass bundle, since want to access info.plist, etc
			results['items'].append(file.File(kextBundle))

		return results
```
