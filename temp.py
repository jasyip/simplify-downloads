import os
import sys
import json
import time
import requests

def check(action, *args, **kwargs):
    while True:
        data = action(*args, **kwargs)
        if data.status_code == requests.codes['ok'] and data.json()['response_code'] != -2:
            return data
        if data.status_code != requests.codes['no_content']:
            sys.exit()
        time.sleep(60)

if __name__ == "__main__":
    with open(os.path.join(sys.path[0], 'api_info.json')) as f:
        api_info = json.load(f)
    params = {'apikey' : api_info['VirusTotal']['api_key']}
    file = {'file' : (sys.argv[1].split('\\')[-1], open(sys.argv[1], 'rb')) }
    data = check(requests.post, api_info['VirusTotal']['url'] + 'scan', files = file, params = params)
    params['resource'] = data.json()['sha256']
    data = check(requests.get, api_info['VirusTotal']['url'] + 'report', params = params).json()
    file['file'][1].close()
    if data['positives'] >= 6:
        os.remove(sys.argv[1])
    print(data)
