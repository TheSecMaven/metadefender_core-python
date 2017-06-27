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
import os
engine = create_engine('sqlite:///IP_Report.db')   #Setup the Database
DBSession = sessionmaker(bind = engine)
session = DBSession()           #Must be able to query database
all_json = 0
os.chdir('/downloads')
def send_request(apikey,ip,url,get_or_post,string):
    write_json = open(sys.argv[2] + "-" +  string + ".json","w")
    output = 0
    url = url + ip
    print url
    if get_or_post == 0:
        output = requests.get(url,headers = {'Authorization':apikey,'Content-type':"application/json"})
    else:
        output = requests.post(url,headers = {'Authorization':apikey, 'Content-type':"application/json"})    
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
    password =
    get_or_post = 0


    url = "https://api.metadefender.com/v3"


    parser = OptionParser()
    #use this option to check a url
    parser.add_option("-u", "--url", dest="s_url", default="none", 
                      help="url to be checked by metadefender core", metavar="scanurl")
    #use this option to get malware associated with an entered url
    parser.add_option("--listcve", "--listcve", dest="list_cve", default="none", 
                      help="returns the list of CVE information that is supported in Metadefender Cloud Usage: '--listcve 1'  ", metavar="scanurl")
    #use this option to check a file's maliciousness
    parser.add_option("--cvesearch", "--cvesearch", dest="s_cvesearch" , default="none",
                      help="search for a CVE using a CVE identifier", metavar="cvesearch")
    #use this option to check a md5 hash in general
    parser.add_option("--app", "--app", dest="s_app" , default="none",
                      help="application to be searched for using md5,sha1, or sha256", metavar="hashvalue")
    #use this option to specify an xfid
    parser.add_option("-v", "--vul", dest="s_vuln" , default="none",
                      help="Search for a vulnerability with a sha1 hash", metavar="vulnerabilty")
    parser.add_option("--hash", "--hash", dest="s_hash" , default="none",
                      help="md5,sha1,or sha256 hash to be searched on metadefender", metavar="hash")
    #use this option to check an ip address
    parser.add_option("-i", "--ip", dest="s_ip" , default="none",
                      help="ip to be checked", metavar="ipaddress")
(options, args) = parser.parse_args()

if len(sys.argv[1:]) == 0:
    parser.print_help()

if ( options.s_ip is not "none" ):
    get_or_post = 0
    apiurl = url + "/ip/"
    ip= options.s_ip
    all_json = send_request(password,ip,apiurl,get_or_post,"IP")
elif (options.s_hash is not "none"):
    get_or_post = 0
    apiurl = url[:-1] + "2/hash/"
    hash_value = options.s_hash
    all_json = send_request(password,hash_value,apiurl,get_or_post,"hash")
elif(options.s_vuln is not "none"):
    get_or_post = 0
    apiurl = url + "/vulnerability/"
    sha1 = options.s_vuln              #Must be a sha1 hash
    all_json = send_request(password,sha1,apiurl,get_or_post,"vulnerability")
elif(options.s_app is not "none"):
    get_or_post = 0
    apiurl = url + "/appinfo/"
    hash_value = options.s_app
    all_json = send_request(password,hash_value,apiurl,get_or_post,"app_info")
elif(options.s_cvesearch is not "none"):
    get_or_post = 0
    apiurl = url + "/cve/"
    cve_identifier = options.s_cvesearch
    all_json = send_request(password,cve_identifier,apiurl,get_or_post,"Lookup")
elif(options.list_cve is not "none"):
    get_or_post = 0
    apiurl = url + "/cve"
    all_json = send_request(password,"",apiurl,get_or_post,"CVELISTING")

if(options.s_ip is not "none" and all_json['data']['detected_by'] > 0 ):
    categories = []
    for source in all_json['data']['scan_results']:
        for entry in source['results']:
            if(entry['assessment'] == "" or entry['assessment'] in categories):
                continue
            else:
                print "Categorization: " + entry['assessment']
                categories.append(entry['assessment'])

