##########################################################
# List of various YARA rule repos we are going to pull out
##########################################################
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
"@ -split "`n" | % { $_.trim() }

$individual_yara = @"
https://gist.githubusercontent.com/pedramamini/c586a151a978f971b70412ca4485c491/raw/68ba7792699177c033c673c7ffccfa7a0ed5ce47/XProtect.yara
https://raw.githubusercontent.com/mandiant/red_team_tool_countermeasures/master/all-yara.yar
https://gist.githubusercontent.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44/raw/d621fcfd496d03dca78f9ff390cad88684139d64/iddqd.yar
https://raw.githubusercontent.com/VectraThreatLab/reyara/master/re.yar
https://raw.githubusercontent.com/Te-k/cobaltstrike/master/rules.yar
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

##########################################################
# Global location variable
##########################################################
# Global variable showing location of temp folder
$temp_location = [System.IO.Path]::GetTempPath()


##########################################################
# Yara Rule processing
##########################################################
# For every URL in the list of project repositories, spawn new download job and make sure it completes
# Use .NET unpack method to unzip the archive
for($counter = 0; $counter -lt $project_repos.Count; $counter++) {
	# Create folder with UUID in temp location
    $temp_folder_name = [System.Guid]::NewGuid() 
    $path = "yaratemp_" + $temp_folder_name 
    $tempDownloadFolder = (Join-Path $temp_location $path)
	New-Item -ItemType Directory -Path $tempDownloadFolder
	Start-Job -Name WebReq -ArgumentList $project_repos[$counter],$tempDownloadFolder -ScriptBlock { 
	param($url,$destinationfolder)
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Invoke-WebRequest -Uri $url -OutFile "$destinationfolder\download.zip"
    [Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem')
    [io.compression.zipfile]::ExtractToDirectory("$destinationfolder\download.zip", "$destinationfolder\")
	}
	Get-Job | Receive-Job
	Wait-Job -Name WebReq
}

# For every URL in the list of project repositories, spawn new download job and make sure it completes
# Use .NET unpack method to unzip the archive
for($counter = 0; $counter -lt $yararepo_urls.Count; $counter++) {
	# Create folder with UUID in temp location
    $temp_folder_name = [System.Guid]::NewGuid() 
    $path = "yaratemp_" + $temp_folder_name 
    $tempDownloadFolder = (Join-Path $temp_location $path)
	New-Item -ItemType Directory -Path $tempDownloadFolder
	
	Start-Job -Name WebReq -ArgumentList $yararepo_urls[$counter],$tempDownloadFolder -ScriptBlock { 
	param($url,$destinationfolder)
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Invoke-WebRequest -Uri $url -OutFile "$destinationfolder\download.zip"
	[Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem')
    [io.compression.zipfile]::ExtractToDirectory("$destinationfolder\download.zip", "$destinationfolder\")
	}
	Get-Job | Receive-Job
	Wait-Job -Name WebReq
}

#For every URL in the list of individual gists and/or other raw yara rule locations
for($counter = 0; $counter -lt $individual_yara.Count; $counter++) {
	# Create folder with UUID in temp location
	$temp_location = [System.IO.Path]::GetTempPath()
        $temp_folder_name = [System.Guid]::NewGuid() 
        $path = "yaratemp_" + $temp_folder_name 
        $tempDownloadFolder = (Join-Path $temp_location $path)
	New-Item -ItemType Directory -Path $tempDownloadFolder
	Start-Job -Name WebReq -ArgumentList $individual_yara[$counter],$tempDownloadFolder -ScriptBlock { 
	param($url,$destinationfolder)
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Invoke-WebRequest -Uri $url -OutFile "$destinationfolder\rules.yar"
	}
	Get-Job | Receive-Job
	Wait-Job -Name WebReq
}

##########################################################
# YARA binary download 
##########################################################
$yaraDownloadLocation = "$temp_location\yara-download"
If(!(test-path $yaraDownloadLocation)) {
  New-Item -ItemType Directory -Force -Path $yaraDownloadLocation
}
# Download yara64 binary to temp folder
$yaraBinaryZip = (Join-Path $yaraDownloadLocation "yara64.zip")
if(!(test-path $yaraBinaryZip)) {
  # Requires TLS 1.2
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara/releases/download/v4.1.3/yara-v4.1.3-1755-win64.zip" -OutFile "$yaraBinaryZip"
}
Expand-Archive -Path $yaraBinaryZip -DestinationPath $yaraDownloadLocation -Force


##########################################################
# YARA Rule cleanup
##########################################################
# Create location in the temp folder for all the yara rules
$tempFileYarLocation = (Join-Path $temp_location "one-rule-for-all.yar")
# Use the following extensions to search all the repos for the rules recursivley
$fileextension = "*.yara","*.yar","*.rule"
# Grab all files with specified extension and merge them
$content_all = (Get-ChildItem "$temp_location\yaratemp_*" -Include ($fileextension) -recurse | Get-Content)
# Clean up non-ASCII characters we find in some of the rules and make sure whatever we write back contains only ASCII
$content_all -replace '[^ -~\t]','' | out-file $tempFileYarLocation -encoding ASCII
# After merging is done, remove all leftover folders and leave just single yara RULE file
Remove-Item –path "$temp_location\yaratemp_*" –recurse -Force

# Rule cleanup based on: https://stackoverflow.com/questions/26849944/remove-duplicate-yara-rules-with-powershell-regular-expressions
# This is not perfect as it won't recognize family tags. These will be skipped
$tempFileYarLocation = (Join-Path $temp_location "one-rule-for-all.yar")
# Read entire file, with all existing rules we found from various repo and replace text that might cause errors in parsing.
# In addition get rid of comments from various locations
$File = [io.file]::ReadAllText($tempFileYarLocation).Replace(": PEiD","").Replace("Yara Rule Set","").Replace("Rule Set","").Replace("private rule","rule").Replace("Generic Rules","").Replace("Additional Rules","")
# Regex pattern to replace comments in the file with an empty space
$file_post_process = $File -replace "(?ms)/\*(?:.|[\r\n])*?\*/", ""
# Regex pattern to find YARA rules
$Pattern = "(?smi)rule(.*?)\{(.*?condition:.*?)\}"
# Extract all matching rules
$ParsedRules = ($file_post_process | Select-String $Pattern -AllMatches)
# A hash table to store all rules
$Rules = @{}
# Find out which rules exist, which are duplicated based on hash table we use to identify rules
$ParsedRules.Matches | Foreach { 
    # Extract rule name
    $Rule = $_.Groups[1].Value.Trim()
    #Extract rule content
    $Content = $_.Groups[2].Value.Trim()
    if ($Rules.ContainsKey($Rule)) {
      Write-Host "Rule Exists, skipping: $Rule"
    # Add the rule if it is not in the hash table
    } else { 
        $Rules.$Rule = $Content
        Write-Host "Rule Added: $Rule"
    } 
}


##########################################################
# YARA rule testing
##########################################################
# Append header to our file storing cleaned up YARA rules before we write all the rules there.
$nondup_file = (Join-Path $temp_location yararule_nonduplicatedrules.yar) 
# Create global import table so all rules can use it
$header_yara_rule = @" 
import "pe"
import "math" 
import "elf" 
import "hash" 
`n
"@
# Append Header to file so we use most common modules
$header_yara_rule | out-file -Encoding ascii $nondup_file

# Create test file for yara matches as yara does not have capability to verify content of rule file without trying to match something
$temp_file_for_compile = (Join-Path $temp_location yararule_compiled.yar) 
$test_file_for_rule_out = (Join-Path $temp_location yararule_testfile.txt) 
"123" | out-file $test_file_for_rule_out

# For each identified YARA rule we need to test and insert only rules that actually work.
$Rules.GetEnumerator() | ForEach-Object { 
    
$yaracbin = "$yaraDownloadLocation\yara64.exe"	

# We use this for testing rule. Import most common modules and stick rule content in based on regex
$string = @" 
import "pe"
import "math"
import "elf" 
import "hash"
`n
rule $($_.Key) {`n $($_.Value) `n}
"@
# Insert temp rule into testing file and carry on with analysis
$string | out-file -Encoding ascii $temp_file_for_compile


# Execute process for testing YARA rule we identified and inserted into temp file
$arg_params = "-m $temp_file_for_compile $test_file_for_rule_out"
$compiler_output_string = (Join-Path $temp_location yararule_compile_output.txt) 
$compiler_error_string = (Join-Path $temp_location yararule_compile_error.txt) 
$yaracompile_process = Start-Process -FilePath $yaracbin -ArgumentList $arg_params -Wait -RedirectStandardError $compiler_error_string -RedirectStandardOut $compiler_output_string -WindowStyle hidden -Passthru
$yaracompile_process.WaitForExit()

##########################################################
# Final YARA rule file creation
##########################################################
# Get content of error log and check for 'error' string inside
$error_file = Get-Content $compiler_error_string
$containsWord = $error_file | %{$_ -match "error"}
# If 'error' string in error log, skip the rule, otherwise insert into global file
if ($containsWord -contains $true) {
    Write-Host  "rule $($_.Key) errors out. Skipping"
} else {
    "rule $($_.Key) {`n $($_.Value) `n}`n"  | out-file -Append -Encoding ascii $nondup_file
}
}

##########################################################
# Cleanup and output
##########################################################

Write-Host "[+] Removing leftover files"
Remove-Item –path "$yaraDownloadLocation" –recurse -Force
Remove-Item –path "$compiler_error_string" -Force
Remove-Item –path "$compiler_output_string" -Force
Remove-Item –path "$test_file_for_rule_out" -Force
Remove-Item –path "$temp_file_for_compile" -Force
Remove-Item –path "$tempFileYarLocation" -Force

Write-Host "Clean YARA rule is located in $nondup_file"































