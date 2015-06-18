import requests
import json
import sys
import datetime

# This script is meant for use with Nessus 6 only.  This script was designed using
# Python 3 and uses the requests, json, sys, and datetime libraries.  I assume no
# responsibility for any data lost from use of this script.

# Set current time to current Epoch time.
current_time = datetime.datetime.now(datetime.timezone.utc)

# The time of each scan is in Epch time.  Set to three weeks by default, can be modified.
# To modify this value, visit http://www.epochconverter.com/ or use the chart below:
# 1 hour	3600 seconds
# 1 day	86400 seconds
# 1 week	604800 seconds
# 1 month (30.44 days) 	2629743 seconds
# 1 year (365.24 days) 	 31556926 seconds

deleteFrom = 1814400

unix_timestamp = int(current_time.timestamp()) - deleteFrom

# This will disable warnings about Unverified HTTPs requests being made.
# I've disabled this in my environment but you can comment this out if
# you want the warnings.
requests.packages.urllib3.disable_warnings()

# Fill in these variables with the information required.
# 'https://EnterNessusIP:8834'
url = ''
verify = False
token = ''
username = ''
password = ''



def build_url(resource):
    # Build our URL
    return '{0}{1}'.format(url, resource)

def connect(method, resource, data=None):
    # Sets the headers, which is X-Cookie (for our token), and
    # content-type.

    headers = {'X-Cookie': 'token={0}'.format(token),
               'content-type': 'application/json'}

    data = json.dumps(data)


    # If statements to determine the method used for the specified API Call
    if method == 'POST':
        r = requests.post(build_url(resource), data=data, headers=headers, verify=False)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data, headers=headers, verify=False)
    else:
        r = requests.get(build_url(resource), params=data, headers=headers, verify=False)

   # Exit if there is an error.
    if r.status_code != 200:
        e = r.json()
        print (e['error'])
        sys.exit()

    return r.json()


def login(usr, pwd):
    # Our method to log into Nessus, which returns our token.

    login = {'username': usr, 'password': pwd}
    data = connect('POST', '/session', data=login)

    return data['token']

def get_scans():
    # Method to increment through our scans and store the ID of each scan.
    SID = []
    data = connect('GET', '/scans')

    for s in data['scans']:
        SID.append(s['id'])

    return SID

def get_history_ids(SID):
    # Method that uses our list of scan IDs from the previous method, searches through
    # the history of the scan ID, and then pulls out any history IDs that are older than
    # the unix_timestamp variable.

    count = 0;
    for s in SID:
        data = connect('GET', '/scans/{0}'.format(s))
        if data['history'] is not None:
            for d in data['history']:
                if data['history'] is not None:
                    if (d['last_modification_date']) < unix_timestamp:
                        print("/scans/{0}/history/{1} is older than {2} and will be deleted.".format(s, d['history_id'], unix_timestamp))
                        deleteHistory(s, d['history_id'])
                        count += 1
        else:
            continue
    return count

def deleteHistory(sid, hid):

    r = requests.delete(build_url('/scans/{0}/history/{1}'.format(sid, hid)), headers={'X-Cookie': 'token={0}'.format(token),'content-type': 'application/json'}, verify=verify)


if __name__ == '__main__':
    print('Logging in...')
    token = login(username, password)

    print("Retrieving scans...")
    scans = get_scans()
    deletedScans = get_history_ids(scans)

    if (deletedScans==1):
        print("{0} scan was deleted.")
    else:
        print("{0} scripts were deleted.".format(deletedScans))
