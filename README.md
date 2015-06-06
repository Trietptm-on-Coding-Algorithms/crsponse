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

####Supported Platforms:####
- Windows

####Notes:####
Compiled crsponse executable located in crsponse/bin/Release/crsponse.zip

If you would like to compile yourself, you will need Microsoft Visual Studio Tools installed on your machine, then run the below command in the crsponse directory.
- **csc /out:crsponse.exe crsponse.cs**
