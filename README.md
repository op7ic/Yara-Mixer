# Yara-Mixer

This repository contains a simple PowerShell script concatenating different Yara rules into one master rule file for ease of use and portability.

## Script Activities:

This script does the following:

* Downloads various YARA rule repositories into temp folder
* Downloads YARA binary into temp folder
* Unpacks various YARA rule repositories into random UUID-named subfolders
* Searches all the repositories for files with extension *.yar, *.rule or *.yara and concatenate them into temporary 'master' file
* For each YARA rule in a temporary 'master' file: 
  * Use regex to extract the content of the rule 
  * Remove YARA rule duplicates
  * Run a simple test to see if rule works without any additional imports or custom modules
  * Remove rules which error out and leave only 'working' rules in new ruleset file
  * Write all working rules to new ruleset file
* Remove any left over files

## Tested On

* Windows Server 2019 x64
* Windows 10 x64

## OpSec

None 