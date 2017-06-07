#Miclain Keffeler
#6/7/2017
#Basic script to query and store the JSON feed that holds the 1000 most recent malicious file hashes. Will be expanded to separate them by hash and make it searchable
#Stores as 'live_feed-<CURRENT_TIME>' so that data could be collected potentially every hour and easily differentiated
import os
import requests
import json
import datetime


filename = "live_feed-" + str(datetime.datetime.now().strftime('%FT%TZ')) + ".json"
output = open("/home/pi/metadefender_core-python/feeds/"+filename,"w")
link = "https://www.metadefender.com/feeds/json?apikey=e912c6be8177a3d9f8101301a450f235"
response1 = ""
response = requests.get(link)
all_json = response.json()
output.write(json.dumps(all_json,indent=4,sort_keys=True))

