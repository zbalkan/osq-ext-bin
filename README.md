## 1. PolyLogyx osquery Extension for Windows

PolyLogyx OSQuery Extension (plgx_win_extension.ext.exe) for Windows platform extends the core [osquery](https://osquery.io/) on Windows by adding real time event collection capabilities to osquery on Windows platform. The capabilities are built using the kernel services library of PolyLogyx. The current release of the extension is a 'community-only' release It is a step in the direction aimed at increasing osquery footprint and adoption on Windows platform. With the extension acting as a proxy into Windows kernel for osquery, the possibilities can be enormous. The version of the current release is 1.0.28.8

# 1.1 What it does:
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
10) An embedded YARA engine to scan files with YARA rules
11) Open Handles in a Process.
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

This additional state of the Windows endpoint is exported by means of following additional tables created by the PolyLogyx Extension

- win_dns_events
- win_dns_response_events 
- win_epp_table
- win_file_events   
- win_file_timestomp_events
- win_http_events 
- win_image_load_events 
- win_image_load_process_map
- win_logger_events
- win_msr
- win_mem_perf
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

The detailed schema for these [tables](https://github.com/polylogyx/osq-ext-bin/tree/master/tables-schema). is available 

## 2 Applying Filters

By default, PolyLogyx client is designed to capture the system events in real time over a wide variety of system activities and make that telemetry available via the flexible SQL syntax of osquery. Given the most of the system activity may be benign, and can cause additional burden of skimming thru a larger volume of data while searching for incidents of interest, we provide a way of filtering the events on most tables.

# 2.1 Types of Filters

Using filters, you can configure the PolyLogyx client to capture only data relevant to you. You can choose to include relevant data and exclude non-meaningful data. In effect you can define these type of filters:
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

2.2 Event filtering support
===========================

Event filters are supported on following tables and columns:

| Table Name                                                  | Column Names                                      |
|-------------------------------------------------------------|---------------------------------------------------|
| win_process_events                                          | cmdline, path, parent_path                        |
| win_registry_events                                         | target_name, action                               |
| win_socket_events                                           | process_name, remote_port, remote_address         |
| win_file_events                                             | target_path, process_name                         |
| win_remote_thread_events                                    | module_name, function_name, src_path, target_path |
| win_process_open_events                                     | src_path, target_path, granted_access             |
| win_dns_events                                              | domain_name                                       |
| win_dns_response_events                                     | domain_name                                       |
| win_image_load_events                                       | image_path                                        |
| win_image_load_process_map                                  | image_path                                        |

2.3 Credit for filters
======================

The event filters are inspired from the filters on the popular IR tool
[sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon). The
filtering conditions in osquery.conf file provided with the extension are
derived from the high fidelity sysmon filters built by
[SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) and its fork
by [ion-storm](https://github.com/ion-storm/sysmon-config). Many other
configurations can be created.

3 Application Log Monitoring
----------------------------

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
and PolyLogyx Extension running in the background, the changes to the files can
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

4 Scanning processes for suspicious memory
------------------------------------------

With the version 1.0.27.7, we have integrated the powerful tool [pe-sieve](https://github.com/hasherezade/pe-sieve) as part of our extension. pe-sieve is a very powerful tool that can scan a process for a variety of malicious implants like shell-codes, API hooks, and replaced/injected PE modules (e.g. process hollowing or reflective DLLs). The original tool can found in the [hasherzade](https://github.com/hasherezade) repository. Leveraging the tool, following 2 new tables have been created.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> .schema win_suspicious_process_scan
CREATE TABLE win_suspicious_process_scan(`pid` BIGINT, `process_name` TEXT, `modules_scanned` BIGINT, `modules_suspicious` BIGINT, `modules_replaced` BIGINT, `modules_detached` BIGINT, `modules_hooked` BIGINT, `modules_implanted` BIGINT, `modules_skipped` BIGINT, `modules_errors` BIGINT);
osquery> .schema win_suspicious_process_dump
CREATE TABLE win_suspicious_process_dump(`pid` BIGINT, `process_name` TEXT, `process_dumps_location` TEXT);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The table "win_suspicious_process_scan" can be used to scan and get the scan results. It however does not generate any memory dump of suspicious artefacts. If the result of scanning a process (or processes) indicate suspiciousness, the summary report, tag report, shell code dump and the entire memory dump can be generated by triggering a query to the table "win_suspicious_process_dump". The output of the table will point to the folder where the reports are placed. These reports and the memory dumps can then be pulled with the help of 'carves' table of osquery, for deeper analysis.

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


5 SSL/TLS certificates monitoring
------------------------------------------

With the version 1.0.28.8, we have introduced a table that captures the SSL/TLS credentials for every TLS connection from the agent. 

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
osquery> osquery> .schema win_ssl_events
CREATE TABLE win_ssl_events(`event_type` TEXT, `action` TEXT, `eid` TEXT, `subject_name` TEXT, `issuer_name` TEXT, `serial_number` TEXT, `dns_names` TEXT, `pid` BIGINT, `process_guid` TEXT, `process_name` TEXT, `remote_address` TEXT, `remote_port` INTEGER, `time` BIGINT, `utc_time` TEXT);
osquery>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Given the vast number of free or stolen TLS certificates, their rampant usage in C2 and Phishing (Domain spoofing), we believe this table can bring a great deal of visibility to counter such attacks. Below is a sample entry of all the websites with ["Let's Encrypt"](https://www.thesslstore.com/blog/lets-encrypt-phishing/) as the CA from a test machine. We believe this level of visbility will help beautiful services like "Let's Encrypt" remain beautiful and their misuse could be restricted.

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A custom flag called **custom_plgx_EnableSSL** needs to be set to true via the osquery options.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"options" :
{
   "custom_plgx_EnableSSL": "true"
},
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

6 Extension SDK
---------------

With the release 1.0.23.3, we have introduced an experimental SDK that allows
the extension to be used as a bridge between an endpoint application and
osquery. For more details, check
[it](https://github.com/polylogyx/osq-ext-bin/tree/master/osq-ext-sdk) out.

7 FAQ
-----

1.  What is extension version?

It is 1.0.28.8. It is digitally signed by PolyLogyx.

2.  What osquery version to use?

It has been built and tested with 3.2.6. It also works with 3.3.0.

3.  I have installed osquery using the MSI from osquery website. Now what?

Stop the osquery service, replace the osquery.flags and osquery.conf with
the ones provided here. Feel free to edit them to bring the configurations
from previous files. Restart osqueryd/osqueryi

4.  Extension is loaded by osqueryd. Can I also see the extension tables by
    running osqueryi?

Unfortunately no. There are multiple reasons for it, one of them being the
communication pipe between osquery core and extension is taken by osqueryd,
so osqueryi won't load the extension.

5.  Does it depend on any kernel component?

It does.

6. Do we need to install the kernel component seperately?

No. The extension executable is self sufficient. The kernel component is
automatically installed/uninstalled with the load and unlaod of extension.
There are however situations when osquery doesn't un-install the extension very
cleanly and the drivers may reamin loaded.

7. Is there a cleanup utility in such a case?

Yes. You can use *\_cleanup.bat.* It would need to be launched from an admin
console

8. osquery has a lot of tables too. What advantage do the extensions' tables
    provide?

osquery tables provide a point-in-time state of the system. The extension
tables are evented tables and therefore remove any blind spot between 2
queries. Both the form factors have their own distinct advantages. On top of
it, the extension enables osquery to be a single agent for all data
collection needs from the endpoint i.e. live investigation, real time state
changes, performance monitoring and log monitoring.

9. How to upgrade from the earlier released extension version (e.g 1.0.22.2)?

The clean way of upgrading would be: *Stop the osquery service. Run the cleanup
utility. Replace the file plgx_win_extension.ext.exe. Re-start the service.*
Any previously stored data tables will be lost.

We have also provided a powershell script for a non-disruptive upgrade of extension.
The script needs to be invoked from an admin priviledge command prompt from the osquery's install dir

10. What if something breaks?

You get to keep both the pieces. Isn't that great?

11. Do you also have fleet manager that provides out-of-box support for these
tables and deployment of extension?

Yes, we do. Feel welcome to contact us at info\@polylogyx.com

12. I want to report an issue.

You can log it here, mail to open\@polylogyx.com or find us on [osquery
slack](https://osquery.slack.com/) at channel \# polylogyx-extension

13. The default config provided here seems to be collecting event only via a handful of tables. What's the story there?

Endpoint telemetry, especically from Windows systems, can be overwhelming despite all the filters and white noise suppression. The default config here, therefore, is designed to primarily collect 2 kinds of events i.e. Process Start and Network. This is inspired by the recommendations in this [blog](https://www.redcanary.com/blog/carbon-black-response-splunk-integration) from a famous MDR organization. Nevertheless, you are welcome to tune it to your needs. That's the beauty of osquery i.e. all you need to do is simply add more queries.

14. What kind of performance penalities are introduced by the extension?

The extension is a silent monitoring tool and barely takes any system resources. However, depending on the aggressiveness of the queries, the quality of event filters and the system activity, the performance could vary from system to system. By using the suggested config and flags we have provided, in the worst case also it remaind under 100 MB of RAM usage. However, the differential nature of osquery scheduled queries can add some burden on osquery, but again depending on how much of activity on the system and the query intervals.

15. Any known issues?

There is a small race between application of filters and the event
collection, so for a short windows events that are supposed to be fitered
get captured.
