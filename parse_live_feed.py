#Miclain Keffeler
#6/7/2017
#This script queries the metadefender core API and prints out any past categorizations of a provided IP address.
#More capabiility is being added as well as the storage of all data pulled in a database


from os import listdir
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
from build_database import MD5
import os
engine = create_engine('sqlite:///feeds/IP_Report.db')   #Setup the Database
DBSession = sessionmaker(bind = engine)
session = DBSession()           #Must be able to query database

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

def check_md5_exist(Provided_md5):           #This function confirms whether or not an entry already exists. If so, it returns the entry 
    while(1):
        count = session.query(MD5).filter(MD5.md5 == Provided_md5).count()  
        if count > 0:               #If the entry for this IP exists already (There is 1 occurence of this IP in the table)
            return session.query(MD5).filter(MD5.md5 == Provided_md5).one()
        else:
            new_md5 = MD5(md5 = Provided_md5)
            session.add(new_md5)
            session.commit()
            return 0

def update_table(column_number,input_string,Provided_md5):              #This function will update both current and historic tables for a given column
    columns = ["File_Category","md5","sha1","sha256","threat_name","Published"]
    columner1 = str(columns[column_number])
    
    add_2table = session.query(MD5).filter(MD5.md5 == Provided_md5).one()
    setattr(add_2table,str(literal_column(str(columner1))),str(input_string))   #Update historic table with new information
    session.commit()

def date_parse(date_string):                          #This function parses the date that comes from the raw JSON output and puts it in a Month/Day/Year format
    parsed_date = dateutil.parser.parse(date_string).strftime("%x")
    return parsed_date

def get_current_info(column_number,review_count,Provided_IP,all_json):             #This function pulls current information from JSON output for a handful of keys
 
    keys = ["categoryDescriptions","created","score"]
    attr = keys[column_number]                              #Declarations
    key_count = 0
    current_info = ""

    if attr == "created" or attr == "score":   #If the attribute we are looking for is the created date or score
        return all_json["history"][review_count-1][attr]
    else:
        for key in all_json["history"][review_count-1][attr]:  #For every report except the most recent report (Which is current, not history)
            if (key_count >= 1):
                current_info = current_info + " ," + str(key)
            else:
                current_info = str(key)
                key_count += 1
        return current_info

if __name__ == "__main__":
    path = sys.argv[1]
    onlyfiles = [f for f in listdir(path)]
    for feed_file in onlyfiles:
        print feed_file
        all_json = json.loads(open(path + feed_file).read())
        for entry in all_json:
            print "1"
            check_md5_exist(entry['md5'])    
            update_table(0,entry['file_type_category'],entry['md5'])
            update_table(5,entry['published'],entry['md5'])
            update_table(2,entry['sha1'],entry['md5'])
            update_table(3,entry['sha256'],entry['md5'])
            update_table(4,entry['threat_name'],entry['md5'])








