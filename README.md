# Remove historical data of each scans in Nessus 6 are older than you specify

Connect to Tenable Nessus scanner server, getting all scan ID's and remove all history ID's of each scan ID older than you specify

This script is meant for use with Nessus 6 only.  This script was designed using Python 3 and uses the requests, json, sys, and datetime libraries.  I assume no responsibility for any data lost from use of this script. All operations use Nessus API.

Nessus [documentation](https://docs.tenable.com/nessus/index.htm).

Nessus API documentation https://yourNessusServer:8834/api#/

The time of each scan is in Epch time.  Set to three weeks by default, can be modified.
To modify this value, visit http://www.epochconverter.com/ or use the chart below:
- 1 hour	3600 seconds
- 1 day	86400 seconds
- 1 week	604800 seconds
- 1 month (30.44 days) 	2629743 seconds
- 1 year (365.24 days) 	 31556926 seconds

