## 1. PolyLogyx osquery Extension SDK for Windows

PolyLogyx OSQuery Extension (plgx_win_extension.ext.exe) for Windows platform extends the core [osquery](https://osquery.io/) on Windows by adding real time event collection capabilities to osquery on Windows platform. The extension can also be used as a bridge between a local application and osquery. Using the SDK an application running on the local endpoint can send queries to osquery running in the background

# 1.1 What it does:
The SDK ( a DLL and a header file) allows any local application to be built (or an existing one to leverage) the osquery data by sending the queries. It is not to be confused as an alternate for the osqueryi shell. The shell is a near complete SQL shell that provides a CLI for osquery. However there are certain limitations with the shell

- It can be used for scripting
- It is difficult to consume osquery data via the shell into a 3rd party application (e.g. an MDM or a compliance application)
- It is not straightforward to share extensions between the shell and the daemon.

To overcome these limitations, the PolyLogyx extension provides a bridge by means of which any 3rd party application can send a SQL query to the osquery. To be able to use this SDK, the presence of the extension is therefore a necessity.

# 1.2 Requisites
The SDK can be be used by administrator privileged program only. A non-admin program will not be able to use this bridge into osquery. 

## 2 Sample program

The repository provides a small test program to demonostrate how the queries can be sent and the results be obtained. The test program can be built using Visual Studio 2015 (or greater), or at least that's what it has been tested with. It is too simple a program to create a fancy CMake or any other tool chain around it.

Following shows the sample run and the output for the query against the 'time' table.

c:\>plgx-sdk-test.exe "select * from time;"
datetime: 2018-09-25T17:40:45Z
day: 25
hour: 17
iso_8601: 2018-09-25T17:40:45Z
local_time: 1537897245
local_timezone: UTC
minutes: 40
month: 9
seconds: 45
timestamp: Tue Sep 25 17:40:45 2018 UTC
timezone: UTC
unix_time: 1537897245
weekday: Tuesday
year: 2018
All done
c:\>

## 3 Extension SDK DLL

The extension SDK is shipped as a DLL binary and the calling application needs to load the DLL at runtime, find the exported routine, register a callback and invoke it with the query string. The callback gets invoked in context of the results. In the current version, there is no authtenication or security checks being done. This can even allow a non-admin application to be able to access the osquery data. Comments are invited if the facility needs to be restricted to only admin privileged applications. Given that osqueryi does not need to be admin privileged, we have kept the restrictions out.

## 4 License and other conditions

Check the main repo for License and other conditions