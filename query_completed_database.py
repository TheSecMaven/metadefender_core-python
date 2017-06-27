#!/usr/bin/python
__author__='mkkeffeler'

#Miclain Keffeler
#6/6/2017
#This script queries the database and pulls all information on a provided IP address, both current and historic, and displays it
import time
from build_database import MD5 
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from optparse import OptionParser
import sys
import dateutil.parser
engine = create_engine('sqlite:///feeds/IP_Report.db')
Base = declarative_base()
Base.metadata.bind = engine
from sqlalchemy.orm import sessionmaker
DBSession = sessionmaker(bind = engine)
DBSession.bind = engine
session = DBSession()
# Make a query to find all Persons in the database

def compare_dates(date1,date2):
 
    newdate1 = dateutil.parser.parse(date1).strftime("%x")
    newdate2 = dateutil.parser.parse(date2).strftime('%x')
    if (newdate1 > newdate2):
        return 1
    elif (newdate1 < newdate2):
        return -1
datelist = {}
columns = ["md5","sha1","sha256","threat_name","Published"]
# Retrieve one Address whose person field is point to the person object
# Return the first IP address from all the IP addresses in this table
def print_md5(string):
    print "Registrar Name: " + string

def print_sha1(string):
    print "Registrar Organization: " + string

def print_sha256(string):   #This function is used to print the IP address
    print "IP: " + string

def print_threatname(string):  #This function is used to print the IP location
    print "Location: " + string

def print_Published(string):   #This function is used to print the date of review
    print "Date of Review: " + str(string)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("--all", "--all", dest="all1", default="none",  
                      help="Print all elements of an entry that came after a provided published date D/M/YEAR", metavar="all")         #Prints all elements of the provided IP address
    parser.add_option("--range", "--range", dest="daterange", default="none",  
                      help="Print all elements of an entry that came after a provided published date D/M/YEAR with --all and before the date provided here D/M/YEAR", metavar="all")         #Prints all elements of the provided IP address
 
    parser.add_option("--md5", "--md5", dest="s_md5", default="none", 
                      help="search for a sha1 hash within the database", metavar="current")
    parser.add_option("--sha1", "--sha1", dest="s_sha1" , default="none",
                      help="Search for a sha1 hash within the database", metavar="category")
    parser.add_option("--sha256", "--sha256", dest="s_sha256" , default="none",
                      help="Search for a sha256 hash within the database", metavar="ipaddress")
(options, args) = parser.parse_args()
total_entry = 0
total_count = 0
if options.all1 is not "None" and options.daterange is not "None":

    for hashentry in session.query(MD5).all():
        if (compare_dates(options.all1,hashentry.Published) == 1 and compare_dates(options.daterange,hashentry.Published) == 1): 
             total_entry += 1
             continue
        else:
            print datelist
            print "TOTAL Entries: " + str(total_entry)
            print "Total Entries in Range: " + str(total_count)
            print "_______________________"
            print "MD5: " + hashentry.md5
            print "SHA1: " + hashentry.sha1
            print "SHA256: " + hashentry.sha256
            print "Threat Name: " + hashentry.threat_name
            if (hashentry.Published in datelist):
                datelist[hashentry.Published] += 1 
                print "Published: " + hashentry.Published
                total_count += 1
            else:
                datelist[hashentry.Published] = 1
                print "Published: " + hashentry.Published
                total_count += 1
            total_entry += 1

print datelist

if options.all1 is not "None":

    for hashentry in session.query(MD5).all():
        if (compare_dates(options.all1,hashentry.Published) == 1): 
            total_entry += 1
            continue
        else:
            print "TOTAL Entries: " + str(total_entry)
            print "Total Entries in Range: " + str(total_count)
            print "_______________________"
            print "MD5: " + hashentry.md5
            print "SHA1: " + hashentry.sha1
            print "SHA256: " + hashentry.sha256
            print "Threat Name: " + hashentry.threat_name
            if (hashentry.Published in datelist):
                datelist[hashentry.Published] += 1 
                print "Published: " + hashentry.Published
                total_count += 1
            else:
                datelist[hashentry.Published] = 1
                print "Published: " + hashentry.Published
                total_count += 1
            total_entry += 1

print datelist
if len(sys.argv[1:]) == 0:
    parser.print_help()
