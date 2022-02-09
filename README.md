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
* Print out location of final ruleset file

## Tested On

* Windows Server 2019 x64
* Windows 10 x64

## Excecution time

About 1-2h depending on hardware 

## Use cases

* A compromise assessment looking for anything that could be suspicious against given host/memory/binaries
* An IR case where memory dump is given but you are not sure if something is hiding in the processes and want to check for as many potential matches as possible
* A general scan of the disk/processes when looking for potential 'badness' (especially useful for ICS IR)

## False Positive

As a result of this script, you will end up with one rather large YARA rule file that can be used for scanning multiple environments. Some of the rules will make no sense in the context of what you are investing so other verification methods might be needed to ensure that false positives are eliminated and/or reduced.