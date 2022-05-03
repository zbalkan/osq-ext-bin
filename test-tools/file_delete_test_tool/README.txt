README for filedeletetest tool
------------------------------

The filedeletetest tool makes use of the following sample code published on MSDN which 
shows how to create a file and mark it for deletion when the handle is closed.

https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle#examples

The test tool has 2 options to test file delete events:

1. First it creates a file "c:\test\mytest.bat" using CreateFile() API. 
Then sets FILE_DISPOSITION_INFO DeleteFile to TRUE so that when file handle is closed, it will be deleted automatically.

2. It uses system() API to create a file "c:\test\mytest2.bat" and then delete it via del command.

To run case 1, either run filedeletetest.exe without any argument or with -delbydisp option.
To run case 2, run filedeletetest.exe with -del option.
 
The file filedeletetest.exe in bin/x64 folder is already created for trial.
In order to use it, just copy the tool on your test machine and launch it from cmd.exe. 

Also, source code of the tool is published in src folder (filedeletetest.sln).

Visual Studio used
-------------------
Microsoft Visual Studio Professional 2019
Version 16.8.3


