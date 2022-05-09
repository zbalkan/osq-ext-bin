# EclecticIQ osquery Extension install script with logger

EclecticIQ OSQuery Extension install script installs osquery and EclecticIQ Windows OSQuery Extension (plgx_win_extension.ext.exe) on Windows
by adding real time event collection capabilities to osquery on Windows platform.

## How to use
There are 2 osquery logger plugin options available for configuration in the script: windows_event_log and filesystem. 
Refer [here](https://osquery.readthedocs.io/en/stable/deployment/logging/) for osquery logger plugins feature.

For using these logger options and to see other install options, run agentinstall.ps1 with -help option.   

If no option is provided or -filesystem option is provided while running the script, The script installs osquery (v5.2.2.0) and extension with filesystem logger plugin.
This will generate osquery logs in c:\program files\osquery\log folder.

If -windows_event_log option is provided, osquery and extension will be installed with windows_event_log logger plugin.
This will generate osquery logs in Windows event viewer (Applications and Services Logs -> EclecticIQ -> osquery).

To uninstall the osquery and extension, use -uninstall option.

# FAQ

1.  What is extension version installed with the script?

It is 3.5.1.0. It is digitally signed by EclecticIQ.

2.  What osquery version does it install?

It installs osquery version 5.2.2.

3.  I have installed osquery using the MSI from osquery website. Now what?
Osquery should not be pre-installed. If osquery is already installed, the script will skip the installation.

4. I want to report an issue.

You can log it here, mail to support\@eclecticiq.com or find us on [osquery
slack](https://osquery.slack.com/) at channel \# eclecticiq-polylogyx-extension