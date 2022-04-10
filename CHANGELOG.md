# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Versions before 0.1.0 are untracked


## [Unreleased]

## [0.3.0] - 2022-04-10
### Changed
* Don't use key `CFBundleInfoPlistURL` of `Info.plist` to retrieve `Info.plist` path
* Remove all broad-except
* Scan chrome extensions in order of extension id

### Fixed
* `knockknock.utils.get_installed_apps` fails silently

## [0.2.0] - 2022-03-28
### Added
* Base class for `KnockKnock` plugins

### Changed
* More changes after switch to python 3
  * Requires python 3.8 or above
  * Replace custom message logging with python logging
  * Reduce use of global variables
* Change how it uses [pyobjc](https://pypi.org/project/pyobjc/) and [Yapsy](https://pypi.org/project/Yapsy/)
* Refine init steps
* Put core modules and plugins to under different packages

### Fixed
* Enforce [pylint](https://pypi.org/project/pylint/); apply fixes and workarounds
* Enforce [mypy](https://pypi.org/project/mypy/); apply fixes


## [0.1.0] - 2022-03-22
### Changed
* Run on python 3
  * Not necessary to use Python from bundled with OS 
  * Upgrade [pyobjc](https://pypi.org/project/pyobjc/), [Yapsy](https://pypi.org/project/Yapsy/)
* Enforce formatting by [black](https://pypi.org/project/black/)
* Enforce import sort by [isort](https://pypi.org/project/isort/)
* Reorganize project files structure
* Sort results

[Unreleased]: https://github.com/koyeung/knockknock/compare/0.3.0...HEAD
[0.3.0]: https://github.com/koyeung/knockknock/releases/tag/0.3.0
[0.2.0]: https://github.com/koyeung/knockknock/releases/tag/0.2.0
[0.1.0]: https://github.com/koyeung/knockknock/releases/tag/0.1.0
