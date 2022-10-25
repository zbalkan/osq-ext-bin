# EclecticIQ osquery Extension for Windows

EclecticIQ OSQuery Extension, also known as PolyLogyx Windows OSQuery Extension (plgx_win_extension.ext.exe) and earlier hosted at [PolyLogyx github](https://github.com/polylogyx/osq-ext-bin/) for Windows platform
extends the core [osquery](https://osquery.io/) on Windows by adding real time event collection capabilities to osquery on Windows platform. The capabilities are built using the kernel services library of EclecticIQ. 
The current release of the extension is a 'community-only' release It is a step in the direction aimed at increasing osquery footprint and adoption on Windows platform. With the extension acting as a proxy into Windows kernel
for osquery, the possibilities can be enormous. The extension supports the 64 bit OS versions from Win7 SP1 onwards, however for Win7, make sure the [KB](https://www.microsoft.com/en-us/download/details.aspx?id=46148) is installed. 
The version of the current release is 4.0.0.0 (md5: 96e54d304022fb7ea9e62d9096836104)

## What it does:
The extension bridges the feature gap of osquery on Windows in comparison to MacOS and Linux by adding the following into the osquery:

1) File Integrity Monitoring (FIM)
2) Process Auditing
3) MSR (Model Specific Register) details
4) Removable Media Events
5) A way to track all the PE files on the system
6) Http requests being generated from the system
7) Socket (listen, accept, connect and close) events
8) DNS request and response events
9) A way to track all the executables that get loaded in memory and their certificate
10) An embedded YARA engine to scan files and processes with YARA rules
11) Open Handles in a Process
12) Ability to query the current status of security products installed on the system
13) Integration with an intelligent PowerShell script to analyze PowerShell script logs
14) Ability to track Registry Events in real time
15) Query the state of the endpoint security solution (e.g. AV)
16) Sysmon style events for RemoteThread and OpenProcess
17) Map of process and loaded DLLs (Images)
18) Ability to monitor application specific log files
19) Ability to monitor application performances
20) Scan the memory of processes for implants, shell code, hollowing or reflective DLL loading
21) Ability to generate the memory dumps of such processes
22) Visibility into TLS/SSL traffic
23) Ability to grab Windows Event Logs
24) AMSI scan for malware in files
25) Blocking for file operations, registry operations, and process creation/termination
26) **New in 3.5.1.0**: Distinguished events for file delete operation when Delete disposition is set to True 
27) **New in 4.0.0.0**: New table "win_disk_index" with search capabilities.
28) **New in 4.0.0.0**: New table "win_named_pipe_events" with NAMED_PIPE_CREATE and NAMED_PIPE_DISCONNECT events.
29) **New in 4.0.0.0**: New column "process_name" in win_image_load_events and win_image_load_process_map tables which denotes the first process detected by extension on loading a particular image.
30) **New in 4.0.0.0**: New (hidden) column "sha256" in win_process_events table denoting sha256 hash of the process.  


This additional state of the Windows endpoint is exported by means of following additional tables created by the EclecticIQ Extension

- win_dns_events
- win_dns_response_events 
- win_epp_table
- win_event_log_channels
- win_event_log_data
- win_file_events   
- win_file_timestomp_events
- win_http_events 
- win_image_load_events 
- win_image_load_process_map
- win_logger_events
- win_msr
- win_mem_perf
- win_network_stats
- win_pefile_events 
- win_process_events 
- win_process_handles
- win_process_open_events
- win_process_perf 
- win_registry_events 
- win_remote_thread_events 
- win_removable_media_events 
- win_suspicious_process_scan
- win_suspicious_process_dump
- win_socket_events 
- win_ssl_events
- win_yara_events
- win_yara

The detailed schema for these [tables](https://github.com/eclecticiq/osq-ext-bin/tree/master/tables-schema). is available 

# Search for files on endpoints by using disk indexing (v4.0.0.0 onwards)

This version of extension integrates two important search capabilities i.e one as provided by OSquery through its SQL and 
another by indexing the disk and enabling searching for files in the background. Osquery already has powerful [file](https://www.kolide.com/blog/the-file-table-osquery-s-secret-weapon) table
to query a file's properties on the disk. However the file table requires one to know the location of the file before hand 
and the WHERE clause is mandatory. The wildcards in the SQL syntax do help searching the file in a set of known directories 
but the file table is not suitable to search the file if the search surface is the entire hard disk. The only way to efficiently achieve
that is by indexing the disk in the background. The current version of the extension is built with the ability to index the disk 
in the background which can make searching for a file in the entire hard disk much more efficient and simplified. The search engine 
uses the similar SQL syntax and therefore also supports all kinds of other SQL commands like JOINS with other tables (e.g. hash)

This feature is available on all supported Windows operating systems. Before you can search for a file on endpoints, you must 
enable search capabilities by setting the **custom_plgx_DiskIndexingEnabled** option to true in the config. By default, this option is set to false.

To keep the disk index refreshed, another configuration flag **custom_plgx_DiskIndexingReindexTimeout** is provided which controls if, and when,
re-indexing needs to done. Its value 0 (default) implies indexing will be done only once and never again. Also, minimum custom acceptable value is 300. 
Value 300 means re-indexing would be done only at least after 300 seconds. Recommended value is 86400.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"options" :
{
   "custom_plgx_DiskIndexingEnabled": "true",
   "custom_plgx_DiskIndexingReindexTimeout": "300"
},
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To perform the actual search for the file using the Osquery's SQL syntax, here is an example of a live query you can run.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_disk_index where filename like '%calc.exe%';
+-------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------+---------+
| filename                                                                                                    | path                                                                                                                                                                                           | flags | attribs |
+-------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------+---------+
| calc.exe                                                                                                    | C:\Windows\System32\calc.exe                                                                                                                                                                   | 1     | 262176  |
| C:\Windows\WinSxS\amd64_microsoft-windows-calc_31bf3856ad364e35_10.0.19041.1_none_5faf0ebeba197e78\calc.exe | C:\Windows\System32\calc.exe                                                                                                                                                                   | 1     | 262176  |
| calc.exe                                                                                                    | C:\Windows\WinSxS\wow64_microsoft-windows-calc_31bf3856ad364e35_10.0.19041.1_none_6a03b910ee7a4073\calc.exe                                                                                    | 1     | 262176  |
| C:\Windows\SysWOW64\calc.exe                                                                                | C:\Windows\WinSxS\wow64_microsoft-windows-calc_31bf3856ad364e35_10.0.19041.1_none_6a03b910ee7a4073\calc.exe                                                                                    | 1     | 262176  |
| calc.exe                                                                                                    | C:\test\calc.exe                                                                                                                                                                               | 1     | 262176  |
| win32calc.exe                                                                                               | C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~19041.2130.1.9\wow64_microsoft-windows-win32calc_31bf3856ad364e35_10.0.19041.1741_none_c891fec201725574\r\win32calc.exe | 1     | 0       |
| win32calc.exe                                                                                               | C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~19041.2130.1.9\wow64_microsoft-windows-win32calc_31bf3856ad364e35_10.0.19041.1741_none_c891fec201725574\f\win32calc.exe | 1     | 0       |
| win32calc.exe                                                                                               | C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~19041.2130.1.9\amd64_microsoft-windows-win32calc_31bf3856ad364e35_10.0.19041.1865_none_be3429f7cd18489c\r\win32calc.exe | 1     | 0       |
| win32calc.exe                                                                                               | C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~19041.2130.1.9\amd64_microsoft-windows-win32calc_31bf3856ad364e35_10.0.19041.1865_none_be3429f7cd18489c\f\win32calc.exe | 1     | 0       |
+-------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------+---------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# Named pipe events (v4.0.0.0 onwards)

EclecticIQ Endpoint Response provides visibility for named pipe events.
By default, this feature is disabled. To enable the feature, you must specify the pipe name to monitor in the config.
Perform these steps to configure event monitoring for a specific pipe.
1. Open the osquery.conf file.
2. Navigate to the plgx_event_filters > win_file_events > target_path > include > values section.
3. Specify the pipe details.
	Add "\\\\unknown drive\\\\\<pipe name\>" to monitor a specific named pipe
	Add "\\\\unknown drive\\\\*" to monitor all named pipes

Here is the sample output of the win_named_pipe_events table.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_named_pipe_events;
+-----------------------+--------------------------------------+-------------------------+------------------------+------------+--------------------------+-------+--------------------------------------+------------------------------------------------+---------+
| action                | eid                                  | target_path             | uid                    | time       | utc_time                 | pid   | process_guid                         | process_name                                   | eventid |
+-----------------------+--------------------------------------+-------------------------+------------------------+------------+--------------------------+-------+--------------------------------------+------------------------------------------------+---------+
| NAMED_PIPE_DISCONNECT | 015E04C8-4D1C-4992-89A1-4A2D00000000 | \UNKNOWN DRIVE\testpipe | Unknown                | 1662473336 | Tue Sep  6 14:08:56 2022 | 9220  | EB128E9D-2DA7-11ED-81A7-F6A576ACB707 | C:\test\server.exe                             | 19      |
| NAMED_PIPE_CREATE     | 7B46FE0C-82AB-413B-9503-247600000000 | \UNKNOWN DRIVE\testpipe | BUILTIN\Administrators | 1662473333 | Tue Sep  6 14:08:53 2022 | 9220  | EB128E9D-2DA7-11ED-81A7-F6A576ACB707 | C:\test\server.exe                             | 19      |
+-----------------------+--------------------------------------+-------------------------+------------------------+------------+--------------------------+-------+--------------------------------------+------------------------------------------------+---------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# File delete by disposition event (v3.5.1.0 onwards)

Windows OS provides more than one method for a file to get deleted. In order to self-delete, malwares like Zero-Access use another trick that would help them evade such monitoring of delete files. 
This method requires that the DeleteFile member of file's FILE_DISPOSITION_INFORMATION be set to TRUE with SetFileInformationByHandle() API.

The test-tools folder contains [filedeletetest](https://github.com/eclecticiq/osq-ext-bin/tree/master/test-tools/file_delete_test_tool) tool  which demonstrates this scenario by first creating a file C:\test\mytest.bat and then deleting it via method described above. 
The sample output of the win_file_events table would look something like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_file_events where action like '%FILE_DELETE_BY_DISP%';
+---------------------+--------------------------------------+-----------------------------+-----+--------+--------+------------------------+------------+--------------------------+---------+------+--------------------------------------+----------------------------------+-----------------+-------------+---------+
| action              | eid                                  | target_path                 | md5 | sha256 | hashed | uid                    | time       | utc_time                 | pe_file | pid  | process_guid                         | process_name                     | amsi_is_malware | byte_stream | eventid |
+---------------------+--------------------------------------+-----------------------------+-----+--------+--------+------------------------+------------+--------------------------+---------+------+--------------------------------------+----------------------------------+-----------------+-------------+---------+
| FILE_DELETE_BY_DISP | 5BFDD450-3238-4AFC-8A64-437F00000000 | C:\test\mytest.bat          |     |        | 0      | BUILTIN\Administrators | 1651056208 | Wed Apr 27 10:43:28 2022 | NO      | 3676 | F7BFEC3E-C60F-11EC-B6E8-6045BDA5C0C0 | C:\test\filedeletetest.exe       |                 |             | 1       |
+---------------------+--------------------------------------+-----------------------------+-----+--------+--------+------------------------+------------+--------------------------+---------+------+--------------------------------------+----------------------------------+-----------------+-------------+---------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# Applying Filters

By default, EclecticIQ client is designed to capture the system events in real time over a wide variety of system activities and make that telemetry available via the flexible SQL syntax of osquery. Given the most of the system activity may be benign, and can cause additional burden of skimming thru a larger volume of data while searching for incidents of interest, we provide a way of filtering the events on most tables.

## Types of Filters

Using filters, you can configure the EclecticIQ client to capture only data relevant to you. You can choose to include relevant data and exclude non-meaningful data. In effect you can define these type of filters:
- Include filters to receive information about events matching the specified filtering criteria.
- Exclude filters to ignore information about events matching the specified filtering criteria.

Note: Exclude filters take precedence over include filters when processing the defined filters. So, if an include and exclude filter match the same event, information is not captured. In the absence of any filters, all events are captured.
These filters operate on the tables and are defined in the osquery.conf file. Use the json syntax to define filters. Here is the syntax used to define a filter.

	“table name”: {
		“column name” : {
			“filter type” : {
				“values”: [
					“value 1”,
					“value 2”
					]


In the syntax:
- **table name** - Represents the name of the table for which to define filters. You must include the table names in quotes (“”). You can apply filters only on a selected set of tables . For more information, see Supported Tables.
- **column name** - Indicates the name of the column within the table on which to filter information. You must include the column names in quotes (“”). You can define filters on selected columns in a set of tables. For more information, see Supported Tables.
- **filter type** - Specifies the filter type. Possible values are include and exclude. You must include the values in quotes (“”).
- **value 1** and **value 2** - List the values to match for the specified filter. Each entry represents a value that you want to store or ignore data for (based on the filter type). You must include the values in quotes (“”). Specified values are case insensitive. You can also use following wild cards in the values.
 
 - \*  Represents one or more characters
 - ?  Represents a single character

Here is an example of exclude filters.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"win_process_events": { 
    "cmdline": {
        "exclude" : {
            "values": 
            [
            "C:\\Windows\\system32\\DllHost.exe /Processid*",
            "C:\\Windows\\system32\\SearchIndexer.exe /Embedding",
            "C:\\windows\\system32\\wermgr.exe -queuereporting",
            ]
            }
        }
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here is an example of include filters.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"win_registry_events": {
    "target_name": {
        "include": {
            "values": 
            [
            "*CurrentVersion\\Run*",
            "*Policies\\Explorer\\Run*",
            "*Group Policy\\Scripts*",
            "*Windows\\System\\Scripts*",
            ]
           }
     }
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## Event filtering support

Event filters are supported on following tables and columns:

| Table Name                                                  | Column Names                                      |
|-------------------------------------------------------------|---------------------------------------------------|
| win_process_events                                          | cmdline, path, parent_path                        |
| win_registry_events                                         | target_name, action, process_name                 |
| win_socket_events                                           | process_name, remote_port, remote_address         |
| win_file_events                                             | target_path, process_name                         |
| win_remote_thread_events                                    | module_name, function_name, src_path, target_path |
| win_process_open_events                                     | src_path, target_path, granted_access             |
| win_dns_events                                              | domain_name                                       |
| win_dns_response_events                                     | domain_name                                       |
| win_image_load_events                                       | image_path                                        |
| win_image_load_process_map                                  | image_path                                        |
| win_ssl_events                                              | process_name                                      |

## Credit for filters

The event filters are inspired from the filters on the popular IR tool
[sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon). The
filtering conditions in osquery.conf file provided with the extension are
derived from the high fidelity sysmon filters built by
[SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) and its fork
by [ion-storm](https://github.com/ion-storm/sysmon-config). Many other
configurations can be created.

# YARA Matching on file events

The extension can be configured to match file events with yara rules. The syntax for configuring yara follows the same 
syntax as in the [osquery](https://osquery.readthedocs.io/en/stable/deployment/yara/). For the current release, only 
the evented version of yara table (win_yara_events) is supported. A sample config would look like following:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"yara": {
   "signatures": {
       "yara_test_group1": [
           "C:\\ProgramData\\osquery\\yara\\eicar.yar"
           ],
       "yara_test_group2": [
           "C:\\ProgramData\\osquery\\yara\\ExampleRule.yar"
           ]
       },
   "file_paths": {
       "test_files_1": [ "yara_test_group1" ],
       "test_files_2": [ "yara_test_group2" ]
       }
   },

   "file_paths": {
       "test_files_1": [ "C:\\Users\\Admin\\Downloads" ],
       "test_files_2": [ "C:\\Users\\Default" ]
   },
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The above config will match yara signatures belonging to **yara_test_group1** to any file created or modified under the folder **C:\Users\Admin\Downloads**
and **yara_test_group2** to files created or modifed under the folder **C:\Users\Default**

The sample output of the win_yara_events table would look something like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_yara_events;
+--------------------------------------+--------------+-----------------------+---------+-------+--------------------------------------+
| target_path                          | category     | action                | matches | count | eid                                  |
+--------------------------------------+--------------+-----------------------+---------+-------+--------------------------------------+
| C:\Users\Default\Downloads\eicar.yar | test_files_2 | FILE Created/Modified |         | 0     | 0ECB4AC8-F5A1-45FB-B55D-6C640CA7FFFF |
| C:\Users\admin\Downloads\hello.txt   | test_files_1 | FILE Created/Modified |         | 0     | 79D16C6D-1DB9-433E-853C-712A0CA7FFFF |
+--------------------------------------+--------------+-----------------------+---------+-------+--------------------------------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

where the **matches** column determines if any of the signature in the yara file matched with the target file and **count** gives the count of rules that matched. For a file event to be considered for matching against the yara signatures, it should also satisfy the file filters criteria.

With the build 1.0.34.14, three new columns have been added in win_yara_events table and they are md5, time, utc_time. This is to improve tracing the events with yara matches.

With the build 1.0.40.1, following yara [externals](https://yara.readthedocs.io/en/v3.4.0/writingrules.html#external-variables) are supported in the rule syntax.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+---------------------------------------------------+---------------------------------------------------+
| External Variable                                 | Column Names                                      |
|---------------------------------------------------|---------------------------------------------------|
| filename                                          | file base name                                    |
| extension                                         | file extension with leading **.**                 |
| filepath                                          | full file path                                    |
| filetype                                          | Upper case extension (DOCX, PDF etc)              |
| md5                                               | file md5 hash                                     |
+---------------------------------------------------+---------------------------------------------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With the support of these external variables, the scope of the yara rules that could be consumed by the engine could vastly improve.

# Application Log Monitoring

With the extension version 1.0.24 a new table has been introduced called
**win_logger_events**. This table can be configured to monitor arbitrary application
log files (e.g. IIS logs, Apache logs, Windows SetupAPI logs etc) as long as the
log is in ASCII format. Each log entry is treated as an **event**, and as new log
entries are populated, the **event** is recorded in the table which can then be
queried using the standard osquery SQL form factor. To avoid indundation of
logs, targeted log collection can be done by provided regex filters. The
win_logger_events table can be configured in the osquery.conf as follows:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"win_logger_plugin": {
    "plugins": 
    [
            {
                "logger_name": "tail",
                "logger_watch_files": 
                [
                    {
                        "watch_file_path": "C:\\temp\\tail.txt"
                    },

                    {
                        "watch_file_path": "C:\\temp\\tail2.txt",
                        "file_regex_pattern" : ["(.*) (\\d+): \\[([^\\]]+)\\] (.*)", "((.|\\r\\n)*)(secret2)(.*)"]
                    }           
                ]
            }   
    ]
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Where **plugins** is an array of different type of log parsers. Currently only
text logs are supported and therefore we call the log parser as 'tail' because
it kind of mimics the unix **tail** functionality. This name can not be changed
when monitoring text based log files. The **logger_watch_files** is an array of
full file paths that need to be monitored, with an optional array of regex
patterns to be matched against each log entry. If no pattern is provided, all
the log entries are captured in the win_logger_events table, or else only those
entries that matched the particular pattern.

In the [test-tools](https://github.com/polylogyx/osq-ext-bin/tree/master/test-tools) folder, a batch file is provided that writes arbitrary data
to files at location c:\temp\tail.txt & c:\temp\tail2.txt. When the batch file is invoked with osquery
and EclecticIQ Extension running in the background, the changes to the files can
be retrieved via the queries to win_logger_events as follows:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from osquery_extensions;
+-------+--------------------+---------+-------------+-------------------------+-----------+
| uuid  | name               | version | sdk_version | path                    | type      |
+-------+--------------------+---------+-------------+-------------------------+-----------+
| 0     | core               | 3.3.1   | 0.0.0       | \\.\pipe\shell.em       | core      |
| 14397 | plgx_win_extension | 1.0.24  | 0.0.0       | \\.\pipe\shell.em.14397 | extension |
+-------+--------------------+---------+-------------+-------------------------+-----------+

osquery> select * from win_logger_events;
+-------------+-------------------+----------------+
| logger_name | logger_watch_file | log_entry      |
+-------------+-------------------+----------------+
| tail        | C:\temp\tail.txt  | hellotail 5
|
| tail        | C:\temp\tail2.txt | secret2        |    
| tail        | C:\temp\tail.txt  | hellotail 4
|
| tail        | C:\temp\tail2.txt | secret2        |
| tail        | C:\temp\tail.txt  | hellotail 2
|
| tail        | C:\temp\tail.txt  | hellotail 3
|
| tail        | C:\temp\tail.txt  | hellotail 8
|
| tail        | C:\temp\tail2.txt | secret2        |
| tail        | C:\temp\tail.txt  | hellotail 7
|
| tail        | C:\temp\tail2.txt | secret2        |
| tail        | C:\temp\tail2.txt | secret2        |
| tail        | C:\temp\tail2.txt | secret2        |
| tail        | C:\temp\tail2.txt | secret2        |
| tail        | C:\temp\tail.txt  | hellotail 1

| tail        | C:\temp\tail.txt  | hellotail 6
|
| tail        | C:\temp\tail2.txt | secret2        |
+-------------+-------------------+----------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Scanning processes for suspicious memory

With the version 1.0.27.7, we have integrated the powerful tool [pe-sieve](https://github.com/hasherezade/pe-sieve) as part of our extension. pe-sieve is a very powerful tool that can scan a process for a variety of malicious implants like shell-codes, API hooks, and replaced/injected PE modules (e.g. process hollowing or reflective DLLs). The original tool can found in the [hasherzade](https://github.com/hasherezade) repository. Leveraging the tool, following 2 new tables have been created.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> .schema win_suspicious_process_scan
CREATE TABLE win_suspicious_process_scan(`pid` BIGINT, `process_name` TEXT, `modules_scanned` BIGINT, `modules_suspicious` BIGINT, `modules_replaced` BIGINT, `modules_detached` BIGINT, `modules_hooked` BIGINT, `modules_implanted` BIGINT, `modules_skipped` BIGINT, `modules_errors` BIGINT);
osquery> .schema win_suspicious_process_dump
CREATE TABLE win_suspicious_process_dump(`pid` BIGINT, `process_name` TEXT, `process_dumps_location` TEXT);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The table "win_suspicious_process_scan" can be used to scan and get the scan results. It however does not generate any memory dump of suspicious artifacts. If the result of scanning a process (or processes) indicate suspiciousness, the summary report, tag report, shell code dump and the entire memory dump can be generated by triggering a query to the table "win_suspicious_process_dump". The output of the table will point to the folder where the reports are placed. These reports and the memory dumps can then be pulled with the help of 'carves' table of osquery, for deeper analysis.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_suspicious_process_scan where process_name="chrome.exe";
+-------+--------------+-----------------+--------------------+------------------+------------------+----------------+-------------------+-----------------+----------------+
| pid   | process_name | modules_scanned | modules_suspicious | modules_replaced | modules_detached | modules_hooked | modules_implanted | modules_skipped | modules_errors |
+-------+--------------+-----------------+--------------------+------------------+------------------+----------------+-------------------+-----------------+----------------+
| 1012  | chrome.exe   | 151             | 1                  | 0                | 0                | 1              | 0                 | 0               | 0              |
| 5240  | chrome.exe   | 39              | 0                  | 0                | 0                | 0              | 0                 | 0               | 0              |
| 1372  | chrome.exe   | 40              | 0                  | 0                | 0                | 0              | 0                 | 0               | 0              |
+-------+--------------+-----------------+--------------------+------------------+------------------+----------------+-------------------+-----------------+----------------+
osquery> select * from win_suspicious_process_dump where pid=1012;
+------+--------------+----------------------------------------------------------------+
| pid  | process_name | process_dumps_location                                         |
+------+--------------+----------------------------------------------------------------+
| 1012 | chrome.exe   | C:\ProgramData\plgx_win_extension\scan_1553264194\process_1012 |
+------+--------------+----------------------------------------------------------------+
osquery> select * from file where directory="C:\ProgramData\plgx_win_extension\scan_1553264194\process_1012";
+-------------------------------------------------------------------------------------------+----------------------------------------------------------------+----------------------------+-------+-----+-----+------+--------+---------+------------+------------+------------+------------+-------+------------+---------+---------+
| path                                                                                      | directory                                                      | filename                   | inode | uid | gid | mode | device | size    | block_size | atime      | mtime      | ctime      | btime | hard_links | symlink | type    |
+-------------------------------------------------------------------------------------------+----------------------------------------------------------------+----------------------------+-------+-----+-----+------+--------+---------+------------+------------+------------+------------+-------+------------+---------+---------+
| C:\ProgramData\plgx_win_extension\scan_1553264194\process_1012\7ffd831f0000.ntdll.dll     | C:\ProgramData\plgx_win_extension\scan_1553264194\process_1012 | 7ffd831f0000.ntdll.dll     | 0     | 0   | 0   | 0666 | 2      | 1917440 |            | 1553264195 | 1553264195 | 1553264195 | 0     |            | 0       | regular |
| C:\ProgramData\plgx_win_extension\scan_1553264194\process_1012\7ffd831f0000.ntdll.dll.tag | C:\ProgramData\plgx_win_extension\scan_1553264194\process_1012 | 7ffd831f0000.ntdll.dll.tag | 0     | 0   | 0   | 0666 | 2      | 96      |            | 1553264195 | 1553264195 | 1553264195 | 0     |            | 0       | regular |
| C:\ProgramData\plgx_win_extension\scan_1553264194\process_1012\report.json                | C:\ProgramData\plgx_win_extension\scan_1553264194\process_1012 | report.json                | 0     | 0   | 0   | 0666 | 2      | 452     |            | 1553264195 | 1553264195 | 1553264195 | 0     |            | 0       | regular |
+-------------------------------------------------------------------------------------------+----------------------------------------------------------------+----------------------------+-------+-----+-----+------+--------+---------+------------+------------+------------+------------+-------+------------+---------+---------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# SSL/TLS certificates monitoring

With the version 1.0.30.10, we have introduced a table that captures the SSL/TLS credentials for every TLS connection from the agent.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> .schema win_ssl_events
CREATE TABLE win_ssl_events(`event_type` TEXT, `action` TEXT, `eid` TEXT, `subject_name` TEXT, `issuer_name` TEXT, `serial_number` TEXT, `dns_names` TEXT, `ja3_md5` TEXT, `ja3s_md5` TEXT, `pid` BIGINT, `process_guid` TEXT, `process_name` TEXT, `remote_address` TEXT, `remote_port` INTEGER, `time` BIGINT, `utc_time` TEXT);
osquery>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Given the vast number of free or stolen TLS certificates, their rampant usage in C2 and Phishing (Domain spoofing), we believe this table can bring a great deal of visibility to counter such attacks. Below is a sample entry of all the websites with ["Let's Encrypt"](https://www.thesslstore.com/blog/lets-encrypt-phishing/) as the CA from a test machine. We believe this level of visbility will help beautiful services like "Let's Encrypt" remain beautiful and their misuse could be restricted.

This table also provides a mechanism for TLS connection fingerprinting. The mechanism called [JA3](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967) was invented by Salesforce Engg and is typically implemented at NSMs. We have implemented it at the host level and exported the data using osquery's SQL tables, that can provide complete visibility into SSL connections at every endpoint.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select subject_name, issuer_name, dns_names from win_ssl_events where issuer_name like '%Encrypt%';
+----------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| subject_name                                                               | issuer_name                                                                                          | dns_names                                                                                                                                                           |
+----------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| /CN=*.polylogyx.com,/C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3    | /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3,/O=Digital Signature Trust Co./CN=DST Root CA X3 | DNS:*.polylogyx.com, DNS:polylogyx.com                                                                                                                              |
| /CN=www.iitgoa.ac.in                                                       | /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3                                                  | DNS:www.iitgoa.ac.in                                                                                                                                                |
| /CN=*.polylogyx.com,/C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3    | /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3,/O=Digital Signature Trust Co./CN=DST Root CA X3 | DNS:*.polylogyx.com, DNS:polylogyx.com                                                                                                                              |
| /CN=admin.mutinyhq.com,/C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3 | /C=US/O=Let's Encrypt/CN=Let's Encrypt Authority X3,/O=Digital Signature Trust Co./CN=DST Root CA X3 | DNS:admin.mutinyhq.com, DNS:api.mutinyhq.com, DNS:api.mutinyhq.io, DNS:app.mutinyhq.com, DNS:preview.mutinyhq.com, DNS:referrals.mutinyhq.com, DNS:www.mutinyhq.com |
+----------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
osquery>

osquery> select process_name, ja3_md5, ja3s_md5 from win_ssl_events limit 10;
+--------------------------------------------------------------------------------------------+----------------------------------+----------------------------------+
| process_name                                                                               | ja3_md5                          | ja3s_md5                         |
+--------------------------------------------------------------------------------------------+----------------------------------+----------------------------------+
| C:\Windows\System32\svchost.exe                                                            | bd0bf25947d4a37404f0424edf4db9ad | e8eeb57c97a5bc68cfd37bead3d8484c |
| C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.46.60.0_x64__kzf8qxf38zg5c\SkypeApp.exe | 3b5074b1b5d032e5620f69f9f700ff0e | 5af13b1d120981869f2623b5ecba1611 |
| C:\Windows\System32\svchost.exe                                                            | bd0bf25947d4a37404f0424edf4db9ad | 69c57a57c3a2471528b239078304cee6 |
| C:\Windows\System32\svchost.exe                                                            | 3b5074b1b5d032e5620f69f9f700ff0e | 69c57a57c3a2471528b239078304cee6 |
| C:\Windows\System32\backgroundTaskHost.exe                                                 | 10ee8d30a5d01c042afd7b2b205facc4 | 13a6525bfe9743d5494febd3f60fcacc |
| C:\Program Files (x86)\Microsoft Office\root\Office16\POWERPNT.EXE                         | ce5f3254611a8c095a3d821d44539877 | e7fc1e025bac30623869f38bfe3eebc2 |
| C:\Windows\System32\svchost.exe                                                            | bd0bf25947d4a37404f0424edf4db9ad | 69c57a57c3a2471528b239078304cee6 |
| C:\Windows\System32\svchost.exe                                                            | bd0bf25947d4a37404f0424edf4db9ad | 69c57a57c3a2471528b239078304cee6 |
| C:\Program Files (x86)\Microsoft Office\root\Office16\POWERPNT.EXE                         | ce5f3254611a8c095a3d821d44539877 | d5955b206cc2988061a1880c3803625c |
| C:\Windows\System32\svchost.exe                                                            | bd0bf25947d4a37404f0424edf4db9ad | 3283d8fb83fcff552063fe0baf6416a5 |
+--------------------------------------------------------------------------------------------+----------------------------------+----------------------------------+
osquery>

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A custom flag called **custom_plgx_EnableSSL** needs to be set to true via the osquery options.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"options" :
{
   "custom_plgx_EnableSSL": "true"
},
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Windows Event Log tables

The based osquery tool provided an event driven approach to collect data from Windows Event Log. This requires that the channels from which the events need to be collected have to be provided at the time of provisioning the agent and the tool will restrict the collection of log data to those channels. For purposes of incident response however, the ability to collect any log from any channel (including retrospective logs) is of paramount importance. We have extended osquery's SQL interface in our extension to facilitate this capability making the collection, aggregation and parsing of Windows Event Log data simplified.

With the release 1.0.40.1, two new tables have been provided in the extension. These tables will allow for querying, and collecting, of data from Windows Event Log. These tables are:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> .tables
<snip>
  => win_event_log_channels
  => win_event_log_data
</snip>
osquery>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Querying the first of these tables, win_event_log_channels, will result in answering all the log channels available in the system. Querying the second table will provide the data in a given channel.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_event_log_channels;
+----------------------------------------------------------------------------------------+
| source                                                                                 |
+----------------------------------------------------------------------------------------+
| Windows PowerShell                                                                     |
| Texus                                                                                  |
| System                                                                                 |
| Security                                                                               |
<snip>
| Application                                                                            |
<snip>
| WINDOWS_wmvdecod_CHANNEL                                                               |
| WINDOWS_WMPHOTO_CHANNEL                                                                |
<snip>
| Microsoft-WindowsPhone-Net-Cellcore-CellularAPI/Debug                                  |
| Microsoft-WindowsPhone-Net-Cellcore-CellManager/Debug                                  |
| Microsoft-WindowsPhone-LocationServiceProvider/Debug                                   |
<snip>
| Intel-SST-CFD-HDA/IntelSST                                                             |
| Intel-iaLPSS2-I2C/Performance                                                          |
<snip>
+----------------------------------------------------------------------------------------+
osquery> 

[PS: For the sake of saving the space, majority of the channel names have been snipped out but you get the idea]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The SQL query constraints provide great flexibility to reduce/parse this list. For e.g. to get all the channels from Microsoft-Windows-Kernel, all that is needed is:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

osquery> select * from win_event_log_channels where source like '%Microsoft-Windows-Kernel%';
+------------------------------------------------------------+
| source                                                     |
+------------------------------------------------------------+
| Microsoft-Windows-Kernel-XDV/Analytic                      |
| Microsoft-Windows-Kernel-WHEA/Operational                  |
| Microsoft-Windows-Kernel-WHEA/Errors                       |
| Microsoft-Windows-Kernel-WDI/Operational                   |
| Microsoft-Windows-Kernel-WDI/Debug                         |
| Microsoft-Windows-Kernel-WDI/Analytic                      |
| Microsoft-Windows-Kernel-StoreMgr/Operational              |
| Microsoft-Windows-Kernel-StoreMgr/Analytic                 |
| Microsoft-Windows-Kernel-ShimEngine/Operational            |
| Microsoft-Windows-Kernel-ShimEngine/Diagnostic             |
| Microsoft-Windows-Kernel-ShimEngine/Debug                  |
| Microsoft-Windows-Kernel-Registry/Performance              |
| Microsoft-Windows-Kernel-Registry/Analytic                 |
| Microsoft-Windows-Kernel-Processor-Power/Diagnostic        |
| Microsoft-Windows-Kernel-Process/Analytic                  |
| Microsoft-Windows-Kernel-Prefetch/Diagnostic               |
| Microsoft-Windows-Kernel-Power/Thermal-Operational         |
| Microsoft-Windows-Kernel-Power/Thermal-Diagnostic          |
| Microsoft-Windows-Kernel-Power/Diagnostic                  |
| Microsoft-Windows-Kernel-PnP/Driver Diagnostic             |
| Microsoft-Windows-Kernel-PnP/Device Enumeration Diagnostic |
| Microsoft-Windows-Kernel-PnP/Configuration Diagnostic      |
| Microsoft-Windows-Kernel-PnP/Configuration                 |
| Microsoft-Windows-Kernel-PnP/Boot Diagnostic               |
| Microsoft-Windows-Kernel-Pep/Diagnostic                    |
| Microsoft-Windows-Kernel-Pdc/Diagnostic                    |
| Microsoft-Windows-Kernel-Network/Analytic                  |
| Microsoft-Windows-Kernel-Memory/Analytic                   |
| Microsoft-Windows-Kernel-LiveDump/Analytic                 |
| Microsoft-Windows-Kernel-IoTrace/Diagnostic                |
| Microsoft-Windows-Kernel-IO/Operational                    |
| Microsoft-Windows-Kernel-Interrupt-Steering/Diagnostic     |
| Microsoft-Windows-Kernel-File/Analytic                     |
| Microsoft-Windows-Kernel-EventTracing/Analytic             |
| Microsoft-Windows-Kernel-EventTracing/Admin                |
| Microsoft-Windows-Kernel-Disk/Analytic                     |
| Microsoft-Windows-Kernel-BootDiagnostics/Diagnostic        |
| Microsoft-Windows-Kernel-Boot/Operational                  |
| Microsoft-Windows-Kernel-Boot/Analytic                     |
| Microsoft-Windows-Kernel-ApphelpCache/Operational          |
| Microsoft-Windows-Kernel-ApphelpCache/Debug                |
| Microsoft-Windows-Kernel-ApphelpCache/Analytic             |
| Microsoft-Windows-Kernel-AppCompat/Performance             |
| Microsoft-Windows-Kernel-AppCompat/General                 |
| Microsoft-Windows-Kernel-Acpi/Diagnostic                   |
+------------------------------------------------------------+
osquery>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The next table can be used to get the data in each channel. 

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_event_log_data;
E0514 13:33:07.384126 65388 plgx_win_evt_log_data_table.cpp:41] Provide 'source' as input in query. Use 'win_event_log_channels' table for help.
osquery>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The channel is a mandatory field and can be obtained from the output of the first table. So if we had to get the event logs from "Windows PowerShell", this is all it would take:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_event_log_data where source="Windows PowerShell" limit 5;
+------------+--------------------------------+--------------------+---------------+---------------+---------+------+-------+----------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| time       | datetime                       | source             | provider_name | provider_guid | eventid | task | level | keywords | data                                                                                                                                                                                                                                                                                                                                                                                                                         |
+------------+--------------------------------+--------------------+---------------+---------------+---------+------+-------+----------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1589437351 | 2019-08-20T16:08:54.567261300Z | Windows PowerShell | PowerShell    |               | 600     | 6    | 4     | -1       | {"EventData":{"Data":"Registry,Started,\tProviderName=Registry\r\n\tNewProviderState=Started\r\n\r\n\tSequenceNumber=1\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.18362.145\r\n\tHostId=728ee7fd-8280-4028-855a-d82025d6721d\r\n\tHostApplication=powershell\r\n\tEngineVersion=\r\n\tRunspaceId=\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine="}}       |
| 1589437351 | 2019-08-20T16:08:54.681615900Z | Windows PowerShell | PowerShell    |               | 600     | 6    | 4     | -1       | {"EventData":{"Data":"Alias,Started,\tProviderName=Alias\r\n\tNewProviderState=Started\r\n\r\n\tSequenceNumber=3\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.18362.145\r\n\tHostId=728ee7fd-8280-4028-855a-d82025d6721d\r\n\tHostApplication=powershell\r\n\tEngineVersion=\r\n\tRunspaceId=\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine="}}             |
| 1589437351 | 2019-08-20T16:08:54.681615900Z | Windows PowerShell | PowerShell    |               | 600     | 6    | 4     | -1       | {"EventData":{"Data":"Environment,Started,\tProviderName=Environment\r\n\tNewProviderState=Started\r\n\r\n\tSequenceNumber=5\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.18362.145\r\n\tHostId=728ee7fd-8280-4028-855a-d82025d6721d\r\n\tHostApplication=powershell\r\n\tEngineVersion=\r\n\tRunspaceId=\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine="}} |
| 1589437351 | 2019-08-20T16:08:54.702975600Z | Windows PowerShell | PowerShell    |               | 600     | 6    | 4     | -1       | {"EventData":{"Data":"FileSystem,Started,\tProviderName=FileSystem\r\n\tNewProviderState=Started\r\n\r\n\tSequenceNumber=7\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.18362.145\r\n\tHostId=728ee7fd-8280-4028-855a-d82025d6721d\r\n\tHostApplication=powershell\r\n\tEngineVersion=\r\n\tRunspaceId=\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine="}}   |
| 1589437351 | 2019-08-20T16:08:54.702975600Z | Windows PowerShell | PowerShell    |               | 600     | 6    | 4     | -1       | {"EventData":{"Data":"Function,Started,\tProviderName=Function\r\n\tNewProviderState=Started\r\n\r\n\tSequenceNumber=9\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1.18362.145\r\n\tHostId=728ee7fd-8280-4028-855a-d82025d6721d\r\n\tHostApplication=powershell\r\n\tEngineVersion=\r\n\tRunspaceId=\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine="}}       |
+------------+--------------------------------+--------------------+---------------+---------------+---------+------+-------+----------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
osquery>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Similar queries can be created to collect log data from any channel.


# Extension SDK

With the release 1.0.23.3, we have introduced an experimental SDK that allows
the extension to be used as a bridge between an endpoint application and
osquery. For more details, check
[it](https://github.com/polylogyx/osq-ext-bin/tree/master/osq-ext-sdk) out.

# YARA Matching on process events

The extension can be configured to match process events with yara rules. For the current release, only 
the evented version of yara table (win_yara_events) is supported. A sample config would look like following:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"yara": {
    "signatures": {
      "eicar_test_group": [
        "C:\\Program Files\\osquery\\yara\\eicar.yara"
      ]
    },
   "process_paths": {
      "test_files": [ "eicar_test_group" ]
    },
  "process_paths": {
    "test_files": [ "C:\\mal_prog.exe" ]
  },
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The above config will match yara signatures belonging to **eicar_test_group** to the process launched as **C:\mal_prog.exe**

The sample output of the win_yara_events table would look something like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_yara_events;
+-----------------+----------------------------------+------------+--------------------------+------------+-------------+----------------------+-------+--------------------------------------+ 
| target_path     | md5                              | time       | utc_time                 | category   | action      | matches              | count | eid                                  | 
+-----------------+----------------------------------+------------+--------------------------+------------+-------------+----------------------+-------+--------------------------------------+ 
| C:\mal_prog.exe | a70c1a6c351dea389ff7c8945cc2f782 | 1632919109 | Wed Sep 29 12:38:29 2021 | test_files | PROC_CREATE | eicar_substring_test | 1     | 09352BC7-20FB-11EC-B6AA-B5B920D119A3 | 
+-----------------+----------------------------------+------------+--------------------------+------------+-------------+----------------------+-------+--------------------------------------+ 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

where the **matches** column determines if any of the signature in the yara file matched with the in-memory data of the target process and **count** gives the count of rules that matched. 
For a process event to be considered for matching against the yara signatures, it should also satisfy the process filters criteria.


A custom flag called **custom_plgx_EnableYaraProcessScan** needs to be set to true via the osquery options.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"options" :
{
   "custom_plgx_EnableYaraProcessScan": "true"
},
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# AMSI Scan for malware in files

The extension can be configured to do AMSI Scan for malware on files. 
For any file write operation anywhere in the file, the file content from beginning upto maximum 70 bytes will be scanned using AmsiScanBuffer() API. 
If the content is found to be malware, win_file_events will report the file as malware and its byte stream in base64 encoded format.
   
The sample output of the win_file_events table would look something like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_file_events;

+------------+--------------------------------------+-----------------+----------------------------------+------------------------------------------------------------------+--------+------------------------+------------+------------------------------+---------+------+--------------------------------------+---------------------------------+-----------------+--------------------------------------------------------------------------------------------------+ 
| action     | eid                                  | target_path     | md5                              | sha256                                                           | hashed | uid                    | time       | utc_time                     | pe_file | pid  | process_guid                         | process_name                    | amsi_is_malware | byte_stream                                                                                      | 
+------------+--------------------------------------+-----------------+----------------------------------+------------------------------------------------------------------+--------+------------------------+------------+------------------------------+---------+------+--------------------------------------+---------------------------------+-----------------+--------------------------------------------------------------------------------------------------+ 
| FILE_WRITE | 3B0683F4-F5A6-4A11-B7ED-E56C00000000 | C:\malware.txt  | e7e5fa40569514ec442bbdf755d89c2f | 8b3f191819931d1f2cef7289239b5f77c00b079847b9c2636e56854d1e5eff71 | 1      | BUILTIN\Administrators | 1632919298 | Wed Sep 29 12:41:38 2021 UTC | NO      | 7636 | 09352BD7-20FB-11EC-B6AA-B5B920D119A3 | C:\Windows\System32\notepad.exe | YES             | WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoNCg== | 
+------------+--------------------------------------+-----------------+----------------------------------+------------------------------------------------------------------+--------+------------------------+------------+------------------------------+---------+------+--------------------------------------+---------------------------------+-----------------+--------------------------------------------------------------------------------------------------+ 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

where the **amsi_is_malware** column determines if the file is a malware and **byte_stream** gives the base64 encoded file data scanned as malware. 
For a file event to be considered for AMSI scan, it should also satisfy the file filters criteria.


A custom flag called **custom_plgx_EnableAmsiStreamEventData** needs to be set to true via the osquery options.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"options" :
{
   "custom_plgx_EnableAmsiStreamEventData": "true"
},
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# Blocking for file operations, registry operations, and process creation/termination

## Description
Using blocking rules, you can configure agent to block actions, or operations, or events from taking place on a system. These operations are: 

- File Operations 
- Registry Operations 
- Process Launch  
- Process Termination 

You can define multiple rule groups. Each rule group can have a combination of ALLOW and/or BLOCK rule sub groups. 
Each rule group should be mandatorily named as “RuleGroupn” where n is the number indicating its position in array of Rule Groups.
Each ALLOW and BLOCK sub group can have multiple conditions. If there are multiple ALLOW or BLOCK rules, all of them needs to be satisfied (a logical AND condition) within ALLOW or BLOCK sub group during matching at run time. 
Rules in ALLOW sub group is an exception to rules defined in BLOCK sub group. 

The above operations (before actual operation happens on the system) are matched against all configured rule groups, at the time of t. 
If any rule group decides to BLOCK an operation, that rule group is considered winner and operation is blocked regardless of the decision (ALLOW/BLOCK) taken by the other rule groups. If none of the rule groups decides to BLOCK, the operation is allowed. 
In other words ‘BLOCK’ takes precedence. 

Providing a blob or ALLOW or BLOCK in a rule group is not mandatory. In the absence of any blob in a rule group, or a rule group, the operation is always allowed. 
Blocking rules are not applicable to actions done by EclecticIQ agent process, which implies that it can perform all operations regardless of blocking rules configuration. However actions done on EclecticIQ Agent process can be blocked using these rules (e.g Agent protection from termination) 

Wild cards (* and ?) are supported(same as filters) for defining rules. 

## Blocking Rules configuration 

Block/Allow Rules can be defined based on following parameters – 

1. Process Launch
	- Process Name 
	- Parent process Name 
	- Command Line (with which process was launched) 

2. Process Termination
	- Process Name 

3. File Operations
	- Process Name
	- Target File Name 

4. Registry Operations
	- Registry Key Name
	- Process Name 

Example configuration for blocking rules  – 

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"plgx_event_control": { 
    "win_proc_events": { 
      "RuleGroup1": { 
        "allow": {}, 
        "block": { 
          "cmdline": { 
            "values": [ 
              "*cmd.exe" 
            ] 
          }, 
          "parent_process": { 
            "values": [ 
              "*services.exe" 
            ] 
          } 
        } 
      } 
    }, 
    "win_file_events": { 
      "RuleGroup1": { 
        "allow": { 
          "process": { 
            "values": [ 
              	"*osquery*", 
		"*plgx_win_extension.ext.exe"	
            ] 
          }, 
          "target_path": { 
            "values": [ 
              "*\\program files\\osquery\\*"
            ] 
          } 
        }, 
        "block": { 
          "target_path": { 
            "values": [ 
              "*\\program files\\osquery\\*" 
            ] 
          } 
        } 
      } 
    }, 
    "win_registry_events": { 
      "RuleGroup1": { 
        "block": { 
          "key_name": { 
            "values": [ 
              "*microsoft*" 
            ] 
          } 
        } 
      }, 
      "RuleGroup2": { 
        "block": { 
          "key_name": { 
            "values": [ 
              "*google*" 
            ] 
          } 
        } 
      } 
    } 
  }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In the above JSON, the first rule blob is describing a blocking rule for “process events” on the Windows system.  

The blob has 1 rule group and 2 rules in “block” sub group (cmdline contains “cmd.exe” and parent process name contains “services.exe”). 
For this rule group to BLOCK process launch, both block rules need to be satisfied. There is no exception to block rules as “allow” sub group is empty. 

The second rule blob is describing a blocking rule for “file events” on the Windows system.  

The blob has 1 rule group and 1 rule in “block” sub group (target file name path contains “\\program files\\osquery\\”). 
For this rule group to BLOCK file modifications for the target path, this rule needs to be satisfied. 
There are 2 exceptions to the BLOCK rule as defined in “allow” sub group – process name contain "osquery", “plgx_win_extension.ext.exe” and target file name path contains “\\program files\\osquery\\”. 

The third rule blob is describing a blocking rule for “registry events” on the Windows system.  

The blob has 2 rule groups. First rule group has 1 rule in “block” sub group (target registry key name contains “microsoft”). 
For this rule group to BLOCK registry modifications for the target key, this rule needs to be satisfied. There are no exceptions to the BLOCK rule as “allow” sub group is empty. 

Second rule group has 1 rule in “block” sub group (target registry key name contains “google”). 
For this rule group to BLOCK registry modifications for the target key, this rule needs to be satisfied. There are no exceptions to the BLOCK rule as “allow” sub group is empty. 

If either of the 2 rule groups decide to BLOCK, the registry operation is BLOCKED. 

The sample output of the win_event_log_data table for file blocking events would look something like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery>select * from win_event_log_data where source='Application' and provider_name='plgx_win_extension' and data like '%Blocked%'; 

+------------+------------------------------+-------------+--------------------+---------------+---------+------+-------+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+ 
| time       | datetime                     | source      | provider_name      | provider_guid | eventid | task | level | keywords | data                                                                                                                                                                                | 
+------------+------------------------------+-------------+--------------------+---------------+---------+------+-------+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+ 
| 1632918664 | 2021-09-29T12:30:53.8999620Z | Application | plgx_win_extension |               | 0       | 0    | 2     | -1       | {"EventData":{"Data":"plgx_win_extension,{\"action\":\"Blocked\",\"process_name\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\"target_path\":\"C:\\\\foo.txt\",\"type\":\"FILE\"}"}} | 
+------------+------------------------------+-------------+--------------------+---------------+---------+------+-------+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+ 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The sample output of the win_event_log_data table for process blocking events would look something like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery>select * from win_event_log_data where source='Application' and provider_name='plgx_win_extension' and data like '%Blocked%'; 

+------------+------------------------------+-------------+--------------------+---------------+---------+------+-------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+ 
| time       | datetime                     | source      | provider_name      | provider_guid | eventid | task | level | keywords | data                                                                                                                                                                                                                           | 
+------------+------------------------------+-------------+--------------------+---------------+---------+------+-------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+ 
| 1632918954 | 2021-09-29T12:35:23.9327698Z | Application | plgx_win_extension |               | 0       | 0    | 2     | -1       | {"EventData":{"Data":"plgx_win_extension,{\"action\":\"Blocked\",\"cmdline\":\"calc\",\"parent_path\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\",\"path\":\"C:\\\\Windows\\\\System32\\\\calc.exe\",\"type\":\"PROC_CREATE\"}"}} | 
| 1632918954 | 2021-09-29T12:35:23.9347704Z | Application | plgx_win_extension |               | 0       | 0    | 2     | -1       | {"EventData":{"Data":"plgx_win_extension,{\"action\":\"Blocked\",\"path\":\"C:\\\\Windows\\\\System32\\\\calc.exe\",\"type\":\"PROC_TERMINATE\"}"}}                                                                            | 
+------------+------------------------------+-------------+--------------------+---------------+---------+------+-------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+ 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The sample output of the win_event_log_data table for registry blocking events would look something like:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery>select * from win_event_log_data where source='Application' and provider_name='plgx_win_extension' and data like '%Blocked%'; 

+------------+------------------------------+-------------+--------------------+---------------+---------+------+-------+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+ 
| time       | datetime                     | source      | provider_name      | provider_guid | eventid | task | level | keywords | data                                                                                                                                                                                                                    | 
+------------+------------------------------+-------------+--------------------+---------------+---------+------+-------+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+ 
| 1632990507 | 2021-09-30T08:28:14.3120582Z | Application | plgx_win_extension |               | 0       | 0    | 2     | -1       | {"EventData":{"Data":"plgx_win_extension,{\"action\":\"Blocked\",\"process_name\":\"C:\\\\Windows\\\\System32\\\\reg.exe\",\"target_name\":\"\\\\REGISTRY\\\\MACHINE\\\\SOFTWARE\\\\mal_key\",\"type\":\"REGISTRY\"}"}} | 
+------------+------------------------------+-------------+--------------------+---------------+---------+------+-------+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+ 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


A custom flag called **custom_plgx_EnableBlocking** needs to be set to true via the osquery options.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"options" :
{
   "custom_plgx_EnableBlocking": "true"
},
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Switch to enable or disable network packet processing for SSL, DNS, HTTP events

By default, network packets processing is disabled. Hence, SSL, DNS, HTTP events won't be generated. 
 
To enable network packets processing, following custom flags need to be set to true via the osquery options.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"options" :
{
   "custom_plgx_EnableHttp": "true",
   "custom_plgx_EnableDns": "true",
   "custom_plgx_EnableSSL": "true"
},
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  
In order to disable SSL, DNS, HTTP events again after enabling, reset the desired option to "false" and restart the services in order:

- sc stop osqueryd
- sc stop vast
- sc stop vastnw
- sc start osqueryd
  
# Switch to enable or disable shallow SSL events

Shallow SSL events are trimmed down SSL events with no certificate information.
 
To enable shallow SSL events, following custom flags need to be set accordingly via the osquery options.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"options" :
{
   "custom_plgx_EnableSSL": "false",
   "custom_plgx_EnableShallowSSL": "true"   
},
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If both custom_plgx_EnableSSL and custom_plgx_EnableShallowSSL are set to "true", custom_plgx_EnableSSL will take precendence over custom_plgx_EnableShallowSSL.

# Network statistics table

A new table win_network_stats is introduced to dump snapshot of network activity at a point of time

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> select * from win_network_stats;
+------------+------------------------+-------------------+-----------------------------------------+-------------+-----------------------------------------+------------+----------------+----------------+
| process_id | tcp_connection_state   | mac_address       | remote_ip_address                       | remote_port | local_ip_address                        | local_port | incoming_bytes | outgoing_bytes |
+------------+------------------------+-------------------+-----------------------------------------+-------------+-----------------------------------------+------------+----------------+----------------+
| 4          | LISTEN                 | 60-45-BD-72-FC-D1 | 1.2.3.4                                 | 0           | 10.0.0.20                               | 139        | 0              | 0              |
| 1128       | CONNECTION ESTABLISHED | 60-45-BD-72-FC-D1 | 100.200.100.200                         | 25625       | 10.0.0.20                               | 3389       | 667904         | 14458963       |
| 0          | TIME-WAIT              | 60-45-BD-72-FC-D1 | 10.20.30.40                             | 80          | 10.0.0.20                               | 54907      | 0              | 0              |
+------------+------------------------+-------------------+-----------------------------------------+-------------+-----------------------------------------+------------+----------------+----------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# File events on network paths

win_file_events table has been enhanced to show file events on network shares and mounted drives

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery>select * from win_file_events;
+-------------+--------------------------------------+-------------------------------------------------------------------------------------------------+-----+--------+--------+---------+------------+------------------------------+---------+------+--------------------------------------+-------------------------+-----------------+-------------+
| action      | eid                                  | target_path                                                                                     | md5 | sha256 | hashed | uid     | time       | utc_time                     | pe_file | pid  | process_guid                         | process_name            | amsi_is_malware | byte_stream |
+-------------+--------------------------------------+-------------------------------------------------------------------------------------------------+-----+--------+--------+---------+------------+------------------------------+---------+------+--------------------------------------+-------------------------+-----------------+-------------+
| FILE_RENAME | 20B1E186-350D-491E-BC3A-796500000000 | \10.10.10.10\Users\foo\foo2_malicious.bat [Orig: \10.10.10.10\Users\foo\foo__malicious.bat] |     |        | 0      | Unknown | 1641820913 | Mon Jan 10 13:21:53 2022 UTC | NO      | 6484 | 6EA2D0DF-71CE-11EC-B6C2-6045BD72FCD1 | C:\Windows\explorer.exe |                 |             |
+-------------+--------------------------------------+-------------------------------------------------------------------------------------------------+-----+--------+--------+---------+------------+------------------------------+---------+------+--------------------------------------+-------------------------+-----------------+-------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Process events on network paths

win_process_events table has been enhanced to show process events on network shares and mounted drives

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery>select * from win_process_events where path like '%foo%';
+----------------+--------------------------------------+-------+--------------------------------------+---------------------------------------------+--------------------------------------+------------+--------------------------------------+-------------------------+---------------------------+------------+------------------------------+
| action         | eid                                  | pid   | process_guid                         | path                                        | cmdline                              | parent_pid | parent_process_guid                  | parent_path             | owner_uid                 | time       | utc_time                     |
+----------------+--------------------------------------+-------+--------------------------------------+---------------------------------------------+--------------------------------------+------------+--------------------------------------+-------------------------+---------------------------+------------+------------------------------+
| PROC_TERMINATE | 3C0F4C5F-1AEF-482A-988B-1D5400000000 | 14880 | 6EA2D25C-71CE-11EC-B6C2-6045BD72FCD1 | \Device\Mup\10.10.10.10\Users\foo\foo.exe | "\\10.10.10.10\Users\foo\foo.exe"  | 6484       | 6EA2D1DA-71CE-11EC-B6C2-6045BD72FCD1 | C:\Windows\explorer.exe | foo-agent\dev-admin | 1641821818 | Mon Jan 10 13:36:58 2022 UTC |
| PROC_CREATE    | 087F9CBB-60CB-4D4F-B0F1-CE4F00000000 | 14880 | 6EA2D25C-71CE-11EC-B6C2-6045BD72FCD1 | \Device\Mup\10.10.10.10\Users\foo\foo.exe | "\\10.10.10.10\Users\foo\foo.exe"  | 6484       | 6EA2D1DA-71CE-11EC-B6C2-6045BD72FCD1 | C:\Windows\explorer.exe | foo-agent\dev-admin | 1641821816 | Mon Jan 10 13:36:56 2022 UTC |
+----------------+--------------------------------------+-------+--------------------------------------+---------------------------------------------+--------------------------------------+------------+--------------------------------------+-------------------------+---------------------------+------------+------------------------------+
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# FAQ

1.  What is extension version?

It is 4.0.0.0. It is digitally signed by EclecticIQ.

2.  What osquery version to use?

It has been built and tested with 4.7.0. It also works with recent osquery version 5.2.2.

3.  I have installed osquery using the MSI from osquery website. Now what?

Stop the osquery service, replace the osquery.flags and osquery.conf with
the ones provided here. Feel free to edit them to bring the configurations
from previous files. Restart osqueryd/osqueryi. You could also use *\plgxugrade.ps1* powershell script.

4.  Extension is loaded by osqueryd. Can I also see the extension tables by
    running osqueryi?

Unfortunately no. There are multiple reasons for it, one of them being the
communication pipe between osquery core and extension is taken by osqueryd,
so osqueryi won't load the extension.

5.  Does it depend on any kernel component?

It does.

6. Do we need to install the kernel component seperately?

No. The extension executable is self sufficient. The kernel component is
automatically installed and started with the load of extension.
However, the kernel component is not stopped or uninstalled with the unload of extension.

7. Is there a cleanup utility in such a case?

Yes. You can use *\_cleanup.bat.* It would need to be launched from an admin console.
Feel free to edit extension file name or path in _cleanup.bat before running for cleanup.

8. osquery has a lot of tables too. What advantage do the extensions' tables
    provide?

osquery tables provide a point-in-time state of the system. The extension
tables are evented tables and therefore remove any blind spot between 2
queries. Both the form factors have their own distinct advantages. On top of
it, the extension enables osquery to be a single agent for all data
collection needs from the endpoint i.e. live investigation, real time state
changes, performance monitoring and log monitoring.

9. How to upgrade from the earlier released extension version (e.g 3.0.1.0)?

The clean way of upgrading would be: *Stop the osquery service. Run the cleanup
utility. Replace the file plgx_win_extension.ext.exe. Re-start the service.*
Any previously stored data tables will be lost.

We have also provided a powershell script *\plgxugrade.ps1* for a non-disruptive upgrade of extension.
The script needs to be invoked from an admin priviledge command prompt from the osquery's install dir

10. What if something breaks?

You get to keep both the pieces. Isn't that great?

11. Do you also have fleet manager that provides out-of-box support for these
tables and deployment of extension?

Yes, we do. Feel welcome to contact us at support\@eclecticiq.com

12. I want to report an issue.

You can log it here, mail to support\@eclecticiq.com or find us on [osquery
slack](https://osquery.slack.com/) at channel \# eclecticiq-polylogyx-extension

13. The default config provided here seems to be collecting event only via a handful of tables. What's the story there?

Endpoint telemetry, especically from Windows systems, can be overwhelming despite all the filters and white noise suppression. 
The default config here, therefore, is designed to primarily collect 2 kinds of events i.e. Process Start and Network. This is inspired by the recommendations in this [blog](https://www.redcanary.com/blog/carbon-black-response-splunk-integration) from a famous MDR organization. Nevertheless, you are welcome to tune it to your needs. That's the beauty of osquery i.e. all you need to do is simply add more queries.

14. What kind of performance penalities are introduced by the extension?

The extension is a silent monitoring tool and barely takes any system resources. However, depending on the aggressiveness of the queries, the quality of event filters and the system activity, the performance could vary from system to system. By using the suggested config and flags we have provided, in the worst case also it remaind under 100 MB of RAM usage. However, the differential nature of osquery scheduled queries can add some burden on osquery, but again depending on how much of activity on the system and the query intervals.

15. Any known issues?

There is a small race between application of filters and the event collection, so for a short duration, windows events that are supposed to be fitered get captured.

16. Where can I see the logs from extension?

By default, extension logs are written to %ProgramFiles%\plgx_osquery\plgx-win-extension.log

17. How to put a network path for monitoring in filters?

Start the filter string with * followed by single slash (\\). For example, to monitor "target_path" on network for "win_file_events", use:
"*\10.10.10.10\Users\foo\foo2_malicious.bat" as filter string.

Similarly, to monitor "path" on network for "win_process_events", use:
"*\10.10.10.10\Users\foo\foo.exe" as filter string.

18. I need to change my EclecticIQ OSQuery Extension real-time events channel log file size. How can I do that?

By default, event channel log file is configured with a size of 40MB which can accomodate roughly 40k-50k events before log rotation.
To adjust log file size, run the following command on cmd:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cmd>wevtutil sl "PlgxRealTimeEvents/Log" /ms:<size_in_bytes>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
where <size_in_bytes> can be 5242880 for 5MB, or 2097152 for 2MB and so on.

You may need to clear the logs before reducing log file size. To clear the logs, run the following command on cmd:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cmd>wevtutil cl "PlgxRealTimeEvents/Log"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
