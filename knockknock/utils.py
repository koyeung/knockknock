__author__ = "patrick"

import hashlib
import logging
import os
import platform
import plistlib
import re
import subprocess
from pathlib import Path
from typing import Optional, Tuple

import Foundation
import Security
from Foundation import NSURL, NSBundle, NSString
from Security import errSecSuccess

LOGGER = logging.getLogger(__name__)

# minimum supported macOS version
_MIN_OS_VERSION = (12, 0)

# from (carbon) MacErrors.h
kPOSIXErrorEACCES = 100013

# base directory for users
USER_BASE_DIRECTORY = "/Users/"

# process type, not dock
PROCESS_TYPE_BG = 0x0

# process type, dock
PROCESS_TYPE_DOCK = 0x1

# directory containing plugins
PLUGIN_DIR = "plugins"


def is_supported_os():
    """Check if OS version is supported."""
    version = get_os_version()

    major, minor = version.split(".")[:2]

    return (int(major), int(minor)) >= _MIN_OS_VERSION


def get_os_version() -> str:
    """Return macOS version as string, e.g. 12.3."""
    # get version (as string)
    version, _, _ = platform.mac_ver()

    return version


def get_kk_directory() -> Path:
    """Get path of KnockKnock directory."""
    return Path(__file__).parent


def get_plugins_directory() -> Path:
    """Get path of plugin directory."""
    return get_kk_directory() / PLUGIN_DIR


# load a bundle's Info.plist
def loadInfoPlist(bundlePath):

    # dictionary info
    infoDictionary = None

    # wrap
    # ->had some issues with bundleWithPath_()
    try:

        # get main bundle
        mainBundle = NSBundle.bundleWithPath_(bundlePath)
        if mainBundle is not None:

            # get dictionary from Info.plist
            infoDictionary = mainBundle.infoDictionary()

    # ignore
    except:

        pass

    return infoDictionary


# given a loaded plist (e.g. from a bundle)
# ->returns the path of the Info.plist
def getPathFromPlist(loadedPlist):

    # path to plist
    plistPath = None

    # wrap
    try:

        # check for Info plist key
        if "CFBundleInfoPlistURL" in loadedPlist:

            # extract the path
            plistPath = loadedPlist["CFBundleInfoPlistURL"].fileSystemRepresentation()

    # ignore
    except:

        pass

    return plistPath


# get a bundle's executable binary
def getBinaryFromBundle(bundlePath) -> Optional[str]:

    # wrap
    # ->had some issues with bundleWithPath_()
    try:

        # get main bundle
        mainBundle = NSBundle.bundleWithPath_(bundlePath)
        if mainBundle is not None:

            # extract executable path
            binaryPath = mainBundle.executablePath()

            return str(binaryPath) if binaryPath else None

    # ignore
    except:

        pass

    return None


# given a list of paths, expand any '~'s into all users
# ->returned paths are checked here to ensure they exist
def expandPaths(paths):

    # expanded paths
    expandedPaths = []

    # iterate over all paths
    for path in paths:

        # check if it needs expanding
        if "~" in path:

            # expand path and insert list
            # ->expanded paths are checked inside function to ensure that they exist
            expandedPaths.extend(expandPath(path))

        # no expansion necessary
        else:

            # make sure file exist
            if os.path.exists(path):

                # add
                expandedPaths.append(path)

    return expandedPaths


# given a a path, expand '~' into all users
def expandPath(path):

    # expanded paths
    expandedPaths = []

    # get all users
    users = getUsers()

    # iterate over all users
    # ->replace '~' in provided path with user's name
    for user in users:

        # expand path
        # ->case where path starts with '~', insert /User and user name
        if path.startswith("~"):

            # expand
            expandedPath = USER_BASE_DIRECTORY + path.replace("~", user)

        # expand path
        # ->case where '~' is in path, just replace with user name
        else:

            # expand
            expandedPath = path.replace("~", user)

        # ignore non-existant directory
        # ->'user' might be a system account (e.g. _spotlight), so won't have 'real' directories/files
        if not os.path.exists(expandedPath):

            # skip
            continue

        # save expanded path
        expandedPaths.append(expandedPath)

    return expandedPaths


# get all users
def getUsers():

    # wrap
    try:

        # init name
        name = NSString("/Local/Default")

        # init record type
        record_type = NSString("dsRecTypeStandard:Users")

        # get root session and check result
        # ->note: pass None as first arg for default session
        root = Foundation.ODNode.nodeWithSession_name_error_(None, name, None)

        # make query and check result
        query = Foundation.ODQuery.queryWithNode_forRecordTypes_attribute_matchType_queryValues_returnAttributes_maximumResults_error_(
            root, record_type, None, 0, None, None, 0, None
        )

        # get results
        results = query.resultsAllowingPartial_error_(0, None)

        # name is user
        users = [result.recordName() for result in results]

        return users

    # ignore exceptions
    except Exception as e:

        # ignore
        pass

    return []


# load a plist from a file
def loadPlist(path):

    # load/return
    return Foundation.NSDictionary.dictionaryWithContentsOfFile_(path)


# determine if a bundle is a kext
# ->checks CFBundlePackageType for 'KEXT'
def isKext(path):

    # flag indicating bundle is kext
    bundleIsKext = False

    # wrap
    try:

        # load Info.plist
        infoPlist = loadInfoPlist(path)
        if infoPlist is not None and "CFBundlePackageType" in infoPlist:

            # extact package type
            packageType = infoPlist["CFBundlePackageType"]

            # load plist and check 'CFBundlePackageType' for 'KEXT'
            bundleIsKext = packageType.upper() == "KEXT"

    # ignore exceptions
    except Exception as e:

        # print e

        # ignore
        pass

    return bundleIsKext


# check the signature of a file
def checkSignature(file: str):

    # flag indicating is from Apple
    is_apple = False

    # list of authorities
    authorities = []

    # file with spaces escaped
    file = NSString(file).stringByAddingPercentEscapesUsingEncoding_(
        Foundation.NSUTF8StringEncoding
    )

    # init file as url
    path = NSURL.URLWithString_(file)

    # create static code from path and check
    result, static_code = Security.SecStaticCodeCreateWithPath(
        path, Security.kSecCSDefaultFlags, None
    )
    if result != errSecSuccess:

        # when user isn't r00t and error is accessed denied
        # ->treat error as just an INFO (addresses issue of '/usr/sbin/cupsd')
        log_level = (
            logging.INFO
            if (0 != os.geteuid()) and (result == kPOSIXErrorEACCES)
            else logging.WARNING
        )

        LOGGER.log(
            log_level, "SecStaticCodeCreateWithPath('%s') failed with %d", path, result
        )

        return not errSecSuccess, None

    # check signature

    sig_check_flags = (
        Security.kSecCSStrictValidate
        | Security.kSecCSCheckAllArchitectures
        | Security.kSecCSCheckNestedCode
    )

    signed_status, _ = Security.SecStaticCodeCheckValidityWithErrors(
        static_code, sig_check_flags, None, None
    )
    # make sure binary is signed
    # ->then, determine if signed by apple & always extract signing authorities
    if signed_status == errSecSuccess:

        # set requirement string
        # ->check for 'signed by apple'
        requirements_string = NSString("anchor apple")

        # first check if binary is signed by Apple
        # ->create sec requirement
        result, requirement = Security.SecRequirementCreateWithString(
            requirements_string, Security.kSecCSDefaultFlags, None
        )
        if result == errSecSuccess:

            # verify against requirement signature
            result = Security.SecStaticCodeCheckValidity(
                static_code, sig_check_flags, requirement
            )
            if result == errSecSuccess:
                # signed by apple
                is_apple = True

        # get code signing info, including authorities and check
        result, information = Security.SecCodeCopySigningInformation(
            static_code, Security.kSecCSSigningInformation, None
        )

        # check result
        if result != errSecSuccess:
            LOGGER.error("SecCodeCopySigningInformation() failed with %d", result)
            return not errSecSuccess, None

        # get cert chain from dictionary
        cert_chain = information[Security.kSecCodeInfoCertificates]

        # get all certs
        for cert in cert_chain:

            # get cert's common name and check
            result, cert_name = Security.SecCertificateCopyCommonName(cert, None)
            if result != errSecSuccess:
                # just try next
                continue

            # extract cert name and append to list
            # ->this is the authority
            authorities.append(cert_name)

    # return dictionary
    signing_info = {
        # save signed status
        "status": signed_status,
        # save flag indicating file signed by apple
        "isApple": is_apple,
        # save signing authorities
        "authorities": authorities,
    }

    # no errors
    # ->might be unsigned though
    return errSecSuccess, signing_info


# parse a bash file (yes, this is a hack and needs to be improved)
# ->returns a list of all commands that are not within a function
#   see http://tldp.org/LDP/abs/html/functions.html for info about bash functions
def parseBashFile(filePath):

    # list of commands
    commands = []

    # flag indicating code is in function
    inFunction = False

    # number of brackets
    bracketCount = 0

    # wrap
    try:

        # open
        with open(filePath, mode="r") as file:

            # read lines
            lines = file.readlines()

    # just bail on error
    except:

        # bail with empty commands
        return commands

    # parse each line
    # ->looking for commands that aren't commented out, and that are not within a function
    for index in range(0, len(lines)):

        # strip line
        strippedLine = lines[index].strip()

        # skip blank lines
        if not strippedLine:

            # skip
            continue

        # skip comments
        if strippedLine.startswith("#"):

            # skip
            continue

        # keep count of '{' and '{'
        if strippedLine.startswith("{"):

            # inc
            bracketCount += 1

        # keep count of '{' and '{'
        if strippedLine.startswith("}"):

            # dec
            bracketCount -= 1

        # check if in function
        # ->ignore all commands, though care about end of function
        if inFunction:

            # check for end of function
            if strippedLine.startswith("}") and 0 == bracketCount:

                # end of function
                inFunction = False

            # go on
            continue

        # check for function start
        # -> a line ends with () with { on next line
        if (
            strippedLine.endswith("()")
            and index != len(lines) - 1
            and lines[index + 1].strip().startswith("{")
        ):

            # entered function
            inFunction = True

            # go on
            continue

        # check for function start
        # -> a line ends with () {
        if "".join(strippedLine.split()).endswith("(){"):

            # inc
            bracketCount += 1

            # entered function
            inFunction = True

            # go on
            continue

        # ok, got a command, not in a function
        commands.append(strippedLine)

    return commands


def findBundles(startDirectory, pattern, depth):

    # list of files
    matchedBundles = []

    # initial depth of starting dir
    # simply count '/'
    initialDepth = startDirectory.count(os.path.sep)

    # get all directories under directory
    # ->walk top down, so depth checks work
    for root, dirnames, filenames in os.walk(startDirectory, topdown=True):

        # check depth
        # ->null out remaining dirname if depth is hit
        if root.count(os.path.sep) - initialDepth >= depth:

            # null out
            dirnames[:] = []

        # filter directories
        # ->want a bundle that matches the pattern
        for dir in dirnames:

            # full path
            fullPath = os.path.join(root, dir)

            # check if matches patter and is a bundle
            if pattern in dir and Foundation.NSBundle.bundleWithPath_(fullPath):

                # save
                matchedBundles.append(fullPath)

    return matchedBundles


# get all installed apps
# ->invokes system_profiler/SPApplicationsDataType
def getInstalledApps():

    # list of apps
    installedApps = None

    # command-line for system_profiler
    # ->xml, mini, etc.
    commandLine = [
        "system_profiler",
        "SPApplicationsDataType",
        "-xml",
        "-detailLevel",
        "mini",
    ]

    # on newer OS's (10.9+) system_profiler supports a timeout
    if int(get_os_version()[1]) >= 9:

        # add timeout
        commandLine.extend(["-timeout", "60"])

    # wrap
    try:

        # get info about all installed apps via 'system_profiler'
        # ->(string)output is read in as plist
        systemProfileInfo = plistlib.readPlistFromString(
            subprocess.check_output(commandLine)
        )

        # get all installed apps
        # ->under '_items' key
        installedApps = systemProfileInfo[0]["_items"]

    # exception
    except Exception as e:

        # reset
        installedApps = None

    return installedApps


# hash (MD5) a file
# from: http://stackoverflow.com/questions/7829499/using-hashlib-to-compute-md5-digest-of-a-file-in-python-3
def md5sum(filename: str):

    # md5 hash
    digest = None

    # wrap
    try:

        # open
        with open(filename, mode="rb") as f:

            # init hash
            d = hashlib.md5()

            # read in/hash
            while True:

                # read in chunk
                buf = f.read(4096)

                # eof?
                if not buf:
                    # bail
                    break

                # update
                d.update(buf)

            # grab hash
            digest = str(d.hexdigest())

    # exception
    except Exception as e:

        # reset
        digest = None

    return digest


# use 'ps' to get list of running processes
def getProcessList():

    # process info
    processesInfo = {}

    # use ps to get process list
    # ->includes full path + args
    psOutput = subprocess.check_output(
        ["ps", "-ax", "-o" "pid,ppid,uid,etime,command"], encoding="utf-8"
    )

    # parse/split output
    # ->note: first line is skipped as its the column headers
    for line in psOutput.split("\n")[1:]:

        # dictionary for process info
        processInfo = {}

        try:

            # split
            components = line.split()

            # skip path's that don't start with '/
            if len(components) < 5 or "/" != components[4][0]:

                # skip
                continue

            # pid
            # ->key, but also but save oid into dictionary too
            processInfo["pid"] = int(components[0])

            # ppid
            processInfo["ppid"] = int(components[1])

            # uid
            processInfo["uid"] = int(components[2])

            # etime
            # ->convert to abs time
            processInfo["etime"] = convertElapsedToAbs(components[3])

            # path
            # note: this will contains args, but these are removed below
            processInfo["path"] = " ".join(components[4:])

            # add to list
            processesInfo[processInfo["pid"]] = processInfo

        # ignore exceptions
        except:

            # skip
            continue

    # invoke ps again to get process list
    # ->this time just with process pid and name (helps with parsing off args)
    psOutput = subprocess.check_output(
        ["ps", "-ax", "-o", "pid,command", "-c"], encoding="utf-8"
    )

    # parse/split output
    # ->note: first line is skipped as its the column headers
    for line in psOutput.split("\n")[1:]:

        # print '2 LINE: %s' % line

        # split
        components = line.split()

        # sanity check
        if len(components) < 2:

            # skip
            continue

        # pid
        pid = int(components[0])

        # process name
        # ->rest of line
        name = " ".join(components[1:])

        # make sure pid exists
        if pid not in processesInfo:

            # print 'skipping since no proc!'

            # skip
            continue

        # process's full path + args
        fullPath = processesInfo[pid]["path"]

        # wrap
        try:

            # ok, find the process name + ' '
            # ->we'll assume that this is the real end of the full path (e.g. before any args)
            processesInfo[pid]["path"] = fullPath[
                : fullPath.index(name + " ") + len(name)
            ]

            # print 'updated: %s' % processesInfo[pid]['path']

        # ignore ignore exceptions
        except:

            # skip
            continue

    return processesInfo


# iterates over list of processes
# ->finds each parent's top parent (if its not launchd)
def setFirstParent(processes):

    # iterate over all processes
    for pid in processes:

        # get current process
        process = processes[pid]

        # default gpid
        process["gpid"] = -1

        # skip if ppid is 0x0 or 0x1 (launchd)
        if 0x0 == process["ppid"] or 0x1 == process["ppid"]:

            # set to self parent
            process["gpid"] = process["ppid"]

            # do next
            continue

        # sanity check
        if process["ppid"] not in processes:

            # try next
            continue

        # get next parent
        parentProcess = processes[process["ppid"]]

        # search for parent right below launchd (pid 0x1)
        while True:

            # found it?
            if 0x1 == parentProcess["ppid"]:

                # save this as the gpid
                process["gpid"] = parentProcess["pid"]

                # bail
                break

            # sanity check
            if parentProcess["ppid"] not in processes:

                # couldn't find parent's pid
                # ->just save current parent's pid as gpid
                process["gpid"] = parentProcess["pid"]

                # bail
                break

            # try next
            parentProcess = processes[parentProcess["ppid"]]

    return


# classify each process on whether it has a dock icon or not
# ->sets process 'type' key
def setProcessType(processes):

    # iterate over all processes
    for pid in processes:

        # get current process
        process = processes[pid]

        # get processes .app/ (bundle) directory
        appDirectory = findAppDirectory(process["path"])

        # non-apps can't have a dock icon
        if not appDirectory:

            # set as non-dock
            process["type"] = PROCESS_TYPE_BG

            # next
            continue

        # wrap
        try:

            # load Info.plist
            infoPlist = loadInfoPlist(appDirectory)

            # couldn't load plist
            if not infoPlist:

                # set as non-dock
                process["type"] = PROCESS_TYPE_BG

                # next
                continue

            # plist that have a LSUIElement and its set to 0x1
            # ->background app
            if "LSUIElement" in infoPlist and 0x1 == infoPlist["LSUIElement"]:

                # set as non-dock
                process["type"] = PROCESS_TYPE_BG

                # next
                continue

            # get here if its an .app, that doesn't have 'LSUIElement' set
            # ->assume its a dock app
            process["type"] = PROCESS_TYPE_DOCK

        # ignore exceptions
        except:

            # ignore
            continue

    return


# given a binary, find its .app directory
def findAppDirectory(binary):

    # app dir
    appDirectory = None

    # split path
    # ->init w/ binary
    splitPath = binary

    # bail if path doesn't contain '.app'
    if ".app" not in binary:

        # bail
        return None

    # scan back up to .app/
    while "/" != splitPath and not splitPath.endswith(".app"):

        # split and grab directory component
        # ->this will be one directory
        splitPath = os.path.split(splitPath)[0]

    # bail if not found
    if not splitPath.endswith(".app"):

        # bail
        return None

    # open /Contents/Info.plist
    mainBundle = Foundation.NSBundle.bundleWithPath_(splitPath)

    # bail if app's executable matches what was passed in
    if mainBundle is None or mainBundle.executablePath != binary:

        # match, so save .app/ dir
        appDirectory = splitPath

    return appDirectory


# convert elapsed time (from ps -o etime) to absolute time in seceond
# elapsed time format: [[dd-]hh:]mm:ss
def convertElapsedToAbs(elapsedTime):

    # time in seconds
    absoluteTime = 0

    # split on ':' and '-'
    timeComponent = re.split("[: -]", elapsedTime)

    # print 'TIME: %s / %s' % (elapsedTime, timeComponent)

    # seconds always included
    absoluteTime += int(timeComponent[-1])

    # minutes always included
    absoluteTime += int(timeComponent[-2]) * 60

    # hours are optional
    if len(timeComponent) >= 3:

        # add hours
        absoluteTime += int(timeComponent[-3]) * 60 * 60

    # days are optional
    if len(timeComponent) == 4:

        # add hours
        absoluteTime += int(timeComponent[-4]) * 60 * 60 * 24

    return absoluteTime


# finds an executable (a la 'which')
# -> based on: http://nullege.com/codes/search/distutils.spawn.find_executable
def which(binary):

    # split paths
    paths = os.environ["PATH"].split(os.pathsep)

    # iterate over all paths
    # ->build path and see if exists
    for path in paths:

        # build path to candidate
        candidate = os.path.join(path, binary)

        # does it exist?
        if os.path.isfile(candidate):

            # happy
            return candidate

    return None
