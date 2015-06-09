# crsponse
Crypto Ransomware Response Tool  
Copyright (C) 2015 Brett Hawkins  
Twitter Handle: @hawkbluedevil

####Description:####
A response tool to help in determining whether a machine has been infected with Crypto Ransomware.

####Usage:####
- crsponse -user `<user>` -all      Check for files, processes & reg keys
- crsponse -user `<user>` -reg      Check for known effected reg keys
- crsponse -user `<user>` -proc     Check for known effected processes
- crsponse -user `<user>` -files    Check for known effected files

####Examples:####
- crsponse -user bond -all
- crsponse -user batman -reg
- crsponse -user superman -proc
- crsponse -user spiderman -files

####Output Files:####
- All files in relevant Crypto Ransomware directories and 1 subdirectory deep of that directory, such as %AppData% or %ProgramData%.  
  **%computername%_info\%computername%_files.csv**

- All processes running on machine.  
  **%computername%_info\%computername%_processes.csv**

- All registry keys that can be used by Crypto Ransomware.   
  **%computername%_info\%computername%_registry_keys.csv**

- Summary of files, processes, and registry keys. This will remove the "noise", so that you can perform quicker analysis to determine whether a machine is infected with Crypto Ransomware. Crypto Ransomware related files, such as splash screens would be in this summary file. The file will also contain any processes running out of known Crypto Ransomware directories. Lastly, it will contain all registry values in registry keys used by Crypto Ransomware, such as HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
  **%computername%_info\%computername%_files_SUMMARY.csv**

####Supported Platforms:####
- Windows

####Notes:####
Compiled crsponse executable located in **crsponse/bin/Release/crsponse.zip**

If you would like to compile yourself, you will need Microsoft Visual Studio Tools installed on your machine, then run the below command in the crsponse directory.
- **csc /out:crsponse.exe crsponse.cs**
