# Yara-Mixer

<p align="center">
  <img src="https://github.com/op7ic/Yara-Mixer/blob/main/pic/mixer.PNG?raw=true" alt="Yara Mixer"/>
</p>

This repository contains a PowerShell script concatenating different Yara rules into one master rule file for ease of use and portability.

## Script Activities

This script does the following:

* Downloads various YARA rule repositories, individual yara rules and projects which contain custom rules into temp folder.
* Downloads YARA binary into temp folder.
* Unpacks various YARA rule repositories into temp, random UUID-named, subfolders.
* Searches all the repositories for files with extension *.yar, *.rule or *.yara and concatenate them into temporary 'master' file.
* For each YARA rule in a temporary 'master' file: 
  * Use regex to extract the content of the rule. 
  * Remove YARA rule duplicates.
  * Strip non-ASCII characters.
  * Strip rule comments (i.e. ```/* Rule set */```).
  * Run a simple test to see if rule works without any additional imports or custom modules.
  * Remove rules which error out and leave only 'working' rules in new ruleset file.
  * Write all working rules to new ruleset file.
* Remove any left over files.
* Print out location of final ruleset file.

## Tested On

* Windows Server 2019 x64
* Windows 10 x64

## Excecution time

Couple of hours depending on hardware and number of sources. Modify [yaramixer](yaramixer.ps1) to add or remove new yara rule sources.

## Use case

* A compromise assessment looking for anything that could be suspicious against given host, memory or binaries.
* An IR case where memory dump is given but you are not sure if something is hiding in the processes and want to check for as many potential matches as possible against process dumps, VAD or other interesting artefacts. 
* A general scan of the disk/processes when looking for potential 'badness' (especially useful for ICS IR).
* Checking if latest red team process injection can be detected using YARA or matched with known rule sets.
* Verify that red team TTPs can't be easily found using public signatures.

## Adding or Removing YARA Sources

Edit the script to add/remove sources. The following variables are used to store the list of repositories downloaded and parsed by [yaramixer](yaramixer.ps1) script:

```
$yararepo_urls = @"
https://github.com/CyberDefenses/CDI_yara/archive/refs/heads/master.zip
https://github.com/citizenlab/malware-signatures/archive/refs/heads/master.zip
https://github.com/f0wl/yara_rules/archive/refs/heads/main.zip
https://github.com/fboldewin/YARA-rules/archive/refs/heads/master.zip
https://github.com/godaddy/yara-rules/archive/refs/heads/master.zip
https://github.com/InQuest/yara-rules/archive/refs/heads/master.zip
https://github.com/mikesxrs/Open-Source-YARA-rules/archive/refs/heads/master.zip
https://github.com/prolsen/yara-rules/archive/refs/heads/master.zip
https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip
https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip
https://github.com/kevthehermit/YaraRules/archive/refs/heads/master.zip
https://github.com/malpedia/signator-rules/archive/refs/heads/main.zip
https://github.com/prolsen/yara-rules/archive/refs/heads/master.zip
https://github.com/volexity/threat-intel/archive/refs/heads/main.zip
https://github.com/telekom-security/malware_analysis/archive/refs/heads/main.zip
https://github.com/Xumeiquer/yara-forensics/archive/refs/heads/master.zip
https://github.com/advanced-threat-research/Yara-Rules/archive/refs/heads/master.zip
https://github.com/Hestat/lw-yara/archive/refs/heads/master.zip
https://github.com/jeFF0Falltrades/YARA-Signatures/archive/refs/heads/master.zip
https://github.com/SupportIntelligence/Icewater/archive/refs/heads/master.zip
https://github.com/fboldewin/YARA-rules/archive/refs/heads/master.zip
https://github.com/tenable/yara-rules/archive/refs/heads/master.zip
https://github.com/fr0gger/Yara-Unprotect/archive/refs/heads/master.zip
https://github.com/JPCERTCC/jpcert-yara/archive/refs/heads/main.zip
https://github.com/thewhiteninja/yarasploit/archive/refs/heads/master.zip
https://github.com/bartblaze/Yara-rules/archive/refs/heads/master.zip
https://github.com/deadbits/yara-rules/archive/refs/heads/master.zip
https://github.com/ProIntegritate/Yara-rules/archive/refs/heads/master.zip
https://github.com/nshadov/yara-rules/archive/refs/heads/master.zip
https://github.com/sbousseaden/YaraHunts/archive/refs/heads/master.zip
https://github.com/stairwell-inc/threat-research/archive/refs/heads/main.zip
"@ -split "`n" | % { $_.trim() }

$individual_yara = @"
https://gist.githubusercontent.com/pedramamini/c586a151a978f971b70412ca4485c491/raw/68ba7792699177c033c673c7ffccfa7a0ed5ce47/XProtect.yara
https://raw.githubusercontent.com/mandiant/red_team_tool_countermeasures/master/all-yara.yar
https://gist.githubusercontent.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44/raw/d621fcfd496d03dca78f9ff390cad88684139d64/iddqd.yar
https://raw.githubusercontent.com/VectraThreatLab/reyara/master/re.yar
https://raw.githubusercontent.com/Te-k/cobaltstrike/master/rules.yar
https://gist.githubusercontent.com/itsreallynick/a5c10f5c4c19f153117c423ea57dc8d0/raw/ceece1c51abb866f190a01a833e3cd3507d70f86/gen_URLpersistence.yar
https://gist.githubusercontent.com/itsreallynick/79841d4e9a50e0e0d086801441e88983/raw/0d36a7a966588dc0b6e6eb57d21df3af74296210/installutilpayload.yar
https://raw.githubusercontent.com/stvemillertime/ConventionEngine/master/ConventionEngine.yar
"@ -split "`n" | % { $_.trim() }

$project_repos = @"
https://github.com/bwall/bamfdetect/archive/refs/heads/master.zip
https://github.com/airbnb/binaryalert/archive/refs/heads/master.zip
https://github.com/kevoreilly/CAPEv2/archive/refs/heads/master.zip
https://github.com/deadbits/yara-rules/archive/refs/heads/master.zip
https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip
https://github.com/intezer/yara-rules/archive/refs/heads/master.zip
https://github.com/t4d/PhishingKit-Yara-Rules/archive/refs/heads/master.zip
https://github.com/malice-plugins/yara/archive/refs/heads/master.zip
https://github.com/nccgroup/Cyber-Defence/archive/refs/heads/master.zip
"@ -split "`n" | % { $_.trim() }
```

## How to use resulting file

Simply use the rules to scan folder, process or any other location using yara command as seen below.

```
yara64.exe -w -m yararule_nonduplicatedrules.yar C:\Windows\ 
```

## False Positive

As a result of this script, you will end up with one rather large YARA rule file that can be used for scanning multiple environments. Some of the rules will make no sense in the context of what you are investing so other verification methods might be needed to ensure that false positives are eliminated and/or reduced.

## Limitations

Rules with 'Family' tags in the name are skipped right now. 