"""Provide utilities functions."""
__author__ = "patrick"

# names are lazily loaded in pyobjc modules
# pylint: disable=no-name-in-module,no-member

import functools
import hashlib
import importlib.util
import logging
import os
import os.path
import platform
import plistlib
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, NamedTuple, Optional, cast

import Foundation
import Security
from Foundation import NSURL, NSBundle, NSDictionary, NSString
from Security import errSecSuccess

from ._types import ProcessInfo

LOGGER = logging.getLogger(__name__)

# from (carbon) MacErrors.h
kPOSIXErrorEACCES = 100013  # pylint: disable=invalid-name

# process type, not dock
PROCESS_TYPE_BG = 0x0

# process type, dock
PROCESS_TYPE_DOCK = 0x1

#: typed namedtuple for major, minor version
Version = NamedTuple("Version", [("major", int), ("minor", int)])

#: package contains plugins
KNOCKKNOCK_PLUGINS = "knockknock_plugins"


def get_os_version() -> Version:
    """Return major and minor version of macOS."""
    # get version (as string)
    version, _, _ = platform.mac_ver()
    major, minor = version.split(".")[:2]

    return Version(int(major), int(minor))


def get_kk_directory() -> Path:
    """Get path of KnockKnock directory."""
    return Path(__file__).parent


def get_plugins_directory() -> Path:
    """Get path of plugin directory."""
    knockknock_plugins_spec = importlib.util.find_spec(KNOCKKNOCK_PLUGINS)
    assert (
        knockknock_plugins_spec
    ), f"unable to find module spec of {KNOCKKNOCK_PLUGINS}"

    assert (
        knockknock_plugins_spec.submodule_search_locations
    ), f"{KNOCKKNOCK_PLUGINS} submodule_search_locations not exists"
    return Path(knockknock_plugins_spec.submodule_search_locations[0])


def load_info_plist(bundle_path: str):
    """Load a bundle's Info.plist."""
    main_bundle = NSBundle.bundleWithPath_(bundle_path)

    # get dictionary from Info.plist
    return main_bundle.infoDictionary()


def get_path_from_plist(loaded_plist):
    """Return path of Info.plist, given a loaded plist from a bundle."""
    return loaded_plist["CFBundleInfoPlistURL"].fileSystemRepresentation()


def get_binary_from_bundle(bundle_path) -> Optional[str]:
    """Get a bundle's executable binary."""
    main_bundle = NSBundle.bundleWithPath_(bundle_path)
    binary_path = main_bundle.executablePath()

    return str(binary_path) if binary_path else None


def expand_paths(paths: Iterable[str]) -> List[str]:
    """Expand any '~'s into all users, given a list of paths.

    ->returned paths are checked here to ensure they exist
    """
    expanded_checked_paths = []

    for path in paths:
        expanded_checked_paths.extend(expand_path(path))

    return expanded_checked_paths


def expand_path(path: str) -> List[str]:
    """Expand '~' into all users, given a path.

    ->returned paths are checked here to ensure they exist
    """

    def filter_exists(paths: Iterable[str]) -> List[str]:
        # ignore non-existant directory
        # ->'user' might be a system account (e.g. _spotlight),
        # so won't have 'real' directories/files
        return [path_ for path_ in paths if os.path.exists(path_)]

    if path.startswith("~") and not path.startswith(f"~{os.sep}"):
        # e.g. ~username/x/y/z
        return filter_exists([os.path.expanduser(path)])

    if path == "~" or path.startswith(f"~{os.sep}"):
        expanded = (
            os.path.expanduser(path.replace("~", f"~{user}", 1))
            for user in _get_users()
        )
        return filter_exists(expanded)

    return filter_exists([path])


@functools.lru_cache()
def _get_users() -> List[str]:
    """Get all users."""
    name = NSString("/Local/Default")
    # get root session and check result
    # ->note: pass None as first arg for default session
    root = Foundation.ODNode.nodeWithSession_name_error_(None, name, None)

    record_type = NSString("dsRecTypeStandard:Users")
    # make query and check result
    query = Foundation.ODQuery.queryWithNode_forRecordTypes_attribute_matchType_queryValues_returnAttributes_maximumResults_error_(  # pylint: disable=line-too-long
        root, record_type, None, 0, None, None, 0, None
    )

    results = query.resultsAllowingPartial_error_(0, None)

    # name is user
    return [result.recordName() for result in results]


def load_plist(path: str):
    """Load a plist from a file."""
    return NSDictionary.dictionaryWithContentsOfFile_(path)


def is_kext(path: str):
    """Determine if a bundle is a kext.

    checks CFBundlePackageType for 'KEXT'
    """
    info_plist = load_info_plist(path)

    if info_plist and "CFBundlePackageType" in info_plist:

        package_type = info_plist["CFBundlePackageType"]
        return package_type.upper() == "KEXT"

    return False


def check_signature(file: str):
    """Check the signature of a file."""
    # pylint: disable=too-many-locals
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


def parse_bash_file(file_path: str):
    """Parse a bash file.

    (yes, this is a hack and needs to be improved)
     ->returns a list of all commands that are not within a function
    see http://tldp.org/LDP/abs/html/functions.html for info about bash functions
    """
    # list of commands
    commands: List[str] = []

    # flag indicating code is in function
    in_function = False

    # number of brackets
    bracket_count = 0

    # wrap
    try:

        # open
        with open(file_path, mode="r") as file:  # pylint: disable=unspecified-encoding

            # read lines
            lines = file.readlines()

    # just bail on error
    except OSError:

        # bail with empty commands
        return commands

    # parse each line
    # ->looking for commands that aren't commented out, and that are not within a function
    for index, line in enumerate(lines):

        # strip line
        stripped_line = line.strip()

        # skip blank lines
        if not stripped_line:

            # skip
            continue

        # skip comments
        if stripped_line.startswith("#"):

            # skip
            continue

        # keep count of '{' and '{'
        if stripped_line.startswith("{"):

            # inc
            bracket_count += 1

        # keep count of '{' and '{'
        if stripped_line.startswith("}"):

            # dec
            bracket_count -= 1

        # check if in function
        # ->ignore all commands, though care about end of function
        if in_function:

            # check for end of function
            if stripped_line.startswith("}") and bracket_count == 0:

                # end of function
                in_function = False

            # go on
            continue

        # check for function start
        # -> a line ends with () with { on next line
        if (
            stripped_line.endswith("()")
            and index != len(lines) - 1
            and lines[index + 1].strip().startswith("{")
        ):

            # entered function
            in_function = True

            # go on
            continue

        # check for function start
        # -> a line ends with () {
        if "".join(stripped_line.split()).endswith("(){"):

            # inc
            bracket_count += 1

            # entered function
            in_function = True

            # go on
            continue

        # ok, got a command, not in a function
        commands.append(stripped_line)

    return commands


def find_bundles(start_directory: str, pattern: str, depth: int) -> List[str]:
    """Find bundles paths."""
    # list of files
    matched_bundles = []

    # initial depth of starting dir
    # simply count '/'
    initial_depth = start_directory.count(os.path.sep)

    # get all directories under directory
    # ->walk top down, so depth checks work
    for root, dirnames, _ in os.walk(start_directory, topdown=True):

        # check depth
        # ->null out remaining dirname if depth is hit
        if root.count(os.path.sep) - initial_depth >= depth:

            # null out
            dirnames[:] = []

        # filter directories
        # ->want a bundle that matches the pattern
        for dir_ in dirnames:

            # full path
            full_path = os.path.join(root, dir_)

            # check if matches patter and is a bundle
            if pattern in dir_ and Foundation.NSBundle.bundleWithPath_(full_path):

                # save
                matched_bundles.append(full_path)

    return matched_bundles


def get_installed_apps():
    """Get all installed apps.

    ->invokes system_profiler/SPApplicationsDataType
    """
    # list of apps
    installed_apps = None

    # command-line for system_profiler
    # ->xml, mini, etc.
    command_line = [
        "system_profiler",
        "SPApplicationsDataType",
        "-xml",
        "-detailLevel",
        "mini",
    ]

    # on newer OS's (10.9+) system_profiler supports a timeout
    if int(get_os_version()[1]) >= 9:

        # add timeout
        command_line.extend(["-timeout", "60"])

    # wrap
    try:

        # get info about all installed apps via 'system_profiler'
        # ->(string)output is read in as plist
        system_profile_info = plistlib.readPlistFromString(
            subprocess.check_output(command_line)
        )

        # get all installed apps
        # ->under '_items' key
        installed_apps = system_profile_info[0]["_items"]

    # exception
    except Exception:  # pylint: disable=broad-except

        # reset
        installed_apps = None

    return installed_apps


def md5sum(filename: str) -> Optional[str]:
    """Compute hash (MD5) of a file.

    see: https://stackoverflow.com/questions/7829499/using-hashlib-to-compute-md5-digest-of-a-file-in-python-3
    """  # pylint: disable=line-too-long
    try:

        # open
        with open(filename, mode="rb") as file_:

            # init hash
            digest = hashlib.md5()

            # read in/hash
            while True:

                # read in chunk
                buf = file_.read(4096)

                # eof?
                if not buf:
                    # bail
                    break

                # update
                digest.update(buf)

            # grab hash
            return str(digest.hexdigest())

    except FileNotFoundError:
        LOGGER.warning(f"{filename=} not found; cannot compute md5sum")
        return None


def get_process_list() -> Dict[int, ProcessInfo]:
    """Use 'ps' to get list of running processes."""

    # process info
    processes_info = {}

    # use ps to get process list
    # ->includes full path + args
    ps_output = subprocess.check_output(
        ["ps", "-ax", "-o", "pid,ppid,uid,etime,comm"], encoding="utf-8"
    )

    # parse/split output
    # ->note: first line is skipped as its the column headers
    for line in ps_output.split("\n")[1:]:

        # dictionary for process info
        process_info: ProcessInfo = {}

        try:

            # split
            components = line.split()

            # skip path's that don't start with '/
            if len(components) < 5 or "/" != components[4][0]:

                # skip
                continue

            # pid
            # ->key, but also but save oid into dictionary too
            pid = int(components[0])
            process_info["pid"] = pid

            # ppid
            process_info["ppid"] = int(components[1])

            # uid
            process_info["uid"] = int(components[2])

            # etime
            # ->convert to abs time
            process_info["etime"] = convert_elapsed_to_abs(components[3])

            # command path without args
            process_info["path"] = components[4]

            # add to list
            processes_info[pid] = process_info

        except Exception:  # pylint: disable=broad-except
            LOGGER.exception("get_process_list exception happens")
            # skip
            continue

    return processes_info


def set_first_parent(processes: Mapping[int, ProcessInfo]):
    """Find each parent's top parent (if its not launchd)."""

    # iterate over all processes
    for process in processes.values():

        # default gpid
        process["gpid"] = -1

        ppid = cast(int, process["ppid"])

        # skip if ppid is 0x0 or 0x1 (launchd)
        if ppid in (0x0, 0x1):

            # set to self parent
            process["gpid"] = ppid

            # do next
            continue

        # sanity check
        if ppid not in processes:

            # try next
            continue

        # get next parent
        parent_process = processes[ppid]

        # search for parent right below launchd (pid 0x1)
        while True:

            parent_ppid = cast(int, parent_process["ppid"])

            # found it?
            if parent_ppid == 0x1:

                # save this as the gpid
                process["gpid"] = parent_process["pid"]

                # bail
                break

            # sanity check
            if parent_ppid not in processes:

                # couldn't find parent's pid
                # ->just save current parent's pid as gpid
                process["gpid"] = parent_process["pid"]

                # bail
                break

            # try next
            parent_process = processes[parent_ppid]


def set_process_type(processes: Mapping[int, ProcessInfo]):
    """Classify each process on whether it has a dock icon or not.

    ->sets process 'type' key
    """

    # iterate over all processes
    for process in processes.values():

        # get processes .app/ (bundle) directory
        app_directory = find_app_directory(process["path"])

        # non-apps can't have a dock icon
        if not app_directory:

            # set as non-dock
            process["type"] = PROCESS_TYPE_BG

            # next
            continue

        # wrap
        try:

            # load Info.plist
            info_plist = load_info_plist(app_directory)

            # couldn't load plist
            if not info_plist:

                # set as non-dock
                process["type"] = PROCESS_TYPE_BG

                # next
                continue

            # plist that have a LSUIElement and its set to 0x1
            # ->background app
            if "LSUIElement" in info_plist and info_plist["LSUIElement"] == 0x1:

                # set as non-dock
                process["type"] = PROCESS_TYPE_BG

                # next
                continue

            # get here if its an .app, that doesn't have 'LSUIElement' set
            # ->assume its a dock app
            process["type"] = PROCESS_TYPE_DOCK

        # ignore exceptions
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception(f"set_process_type exception caught; {process=}")
            # ignore
            continue


def find_app_directory(binary) -> Optional[str]:
    """Find binary's .app directory."""
    # app dir
    app_directory = None

    # split path
    # ->init w/ binary
    split_path = binary

    # bail if path doesn't contain '.app'
    if ".app" not in binary:

        # bail
        return None

    # scan back up to .app/
    while "/" != split_path and not split_path.endswith(".app"):

        # split and grab directory component
        # ->this will be one directory
        split_path = os.path.split(split_path)[0]

    # bail if not found
    if not split_path.endswith(".app"):

        # bail
        return None

    # open /Contents/Info.plist
    main_bundle = NSBundle.bundleWithPath_(split_path)

    # bail if app's executable matches what was passed in
    if main_bundle is None or main_bundle.executablePath != binary:

        # match, so save .app/ dir
        app_directory = split_path

    return app_directory


def convert_elapsed_to_abs(elapsed_time) -> int:
    """Convert elapsed time (from ps -o etime) to absolute time in seceond.

    elapsed time format: [[dd-]hh:]mm:ss
    """
    # time in seconds
    absolute_time = 0

    # split on ':' and '-'
    time_component = re.split("[: -]", elapsed_time)

    # print 'TIME: %s / %s' % (elapsedTime, timeComponent)

    # seconds always included
    absolute_time += int(time_component[-1])

    # minutes always included
    absolute_time += int(time_component[-2]) * 60

    # hours are optional
    if len(time_component) >= 3:

        # add hours
        absolute_time += int(time_component[-3]) * 60 * 60

    # days are optional
    if len(time_component) == 4:

        # add hours
        absolute_time += int(time_component[-4]) * 60 * 60 * 24

    return absolute_time


def which(binary: str) -> Optional[str]:
    """Find an executable (a la 'which').

    -> based on: http://nullege.com/codes/search/distutils.spawn.find_executable
    """
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
