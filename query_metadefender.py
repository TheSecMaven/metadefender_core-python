#Miclain Keffeler
#6/7/2017
#This script queries the metadefender core API and prints out any past categorizations of a provided IP address.
#More capabiility is being added as well as the storage of all data pulled in a database


import requests
import sys
import json
from optparse import OptionParser
import hashlib
import base64
from sqlalchemy import Column, Text, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import types
from sqlalchemy import exists
import dateutil.parser
from sqlalchemy.sql.expression import literal_column

engine = create_engine('sqlite:///IP_Report.db')   #Setup the Database
DBSession = sessionmaker(bind = engine)
session = DBSession()           #Must be able to query database
write_json = open(sys.argv[2]+".json","w")    #Output all downloaded json to a file

all_json = 0
def send_request(apikey,ip,url,get_or_post):
    output = 0
    url = url + ip
    if get_or_post == 0:
        output = requests.get(url,params = {'address': ip},headers = {'Authorization':apikey,'Content-type':"application/json"})
    else:
        output = requests.post(url,params = {'address': ip}, headers = {'Authorization':apikey, 'Content-type':"application/json"})    
    all_json = output.json()
    write_json.write(json.dumps(all_json,indent=4,sort_keys=True))
    return all_json

def get_md5(filename):
    try:
        f = open(filename,"rb")
        md5 = hashlib.md5((f).read()).hexdigest()
        return md5
    except e:
        print str(e)


if __name__ == "__main__":
#Metadefender API Key and Password associated with your IBMID
    password ='apikey <YOUR_API_KEY>'
    get_or_post = 0


    url = "https://api.metadefender.com/v3"


    parser = OptionParser()
    #use this option to check a url
    parser.add_option("-u", "--url", dest="s_url", default="none", 
                      help="url to be checked by metadefender core", metavar="scanurl")
    #use this option to get malware associated with an entered url
    parser.add_option("-l", "--malwareurl", dest="m_url", default="none", 
                      help="returns the malware associated with the entered url", metavar="scanurl")
    #use this option to check a file's maliciousness
    parser.add_option("-f", "--file", dest="malfile" , default="none",
                      help="file (md5 hash) to be checked by metadefender core", metavar="filename")
    #use this option to check a md5 hash in general
    parser.add_option("-m", "--md5", dest="hash" , default="none",
                      help="hash to be checked by metadefender core", metavar="hashvalue")
    #use this option to specify an xfid
    parser.add_option("-x", "--xfid", dest="s_xfid" , default="none",
                      help="xfid to be used ", metavar="xfid")
    parser.add_option("-c", "--cve", dest="s_cve" , default="none",
                      help="cve, bid, us-cert, uv#, rhsa id to be searched ", metavar="cve-xxx-xxx")
    #use this option to check an ip address
    parser.add_option("-i", "--ip", dest="s_ip" , default="none",
                      help="ip to be checked", metavar="ipaddress")
(options, args) = parser.parse_args()

if ( options.s_ip is not "none" ):
    get_or_post = 0
    apiurl = url + "/ip/"
    ip= options.s_ip
    all_json = send_request(password,ip,apiurl,get_or_post)

if(all_json['data']['detected_by'] > 0):
    print "We had a Detection"
categories = []
for source in all_json['data']['scan_results']:
    for entry in source['results']:
        if(entry['assessment'] == "" or entry['assessment'] in categories):
            continue
        else:
            print "Categorization: " + entry['assessment']
            categories.append(entry['assessment'])
