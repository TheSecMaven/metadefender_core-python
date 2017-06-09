#Miclain Keffeler
#6/6/2017
#This file creates 2 tables within the SQL Database that is named "IP_Report.db". One table is used to hold current information while the other is used to hold historic information
import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()
class MD5(Base):    #Table to hold most up to date score and Category on a given IP Address 
    __tablename__ = 'File_Type'               
    File_Category = Column(String(250),nullable=True)       #Here we define each column in the table, Notice that each column is also a normal Python instance attribute.
    md5 = Column(String(500),primary_key=True)
    sha1 = Column(String(250),nullable=True) 
    sha256 = Column(String(250), nullable=True)
    threat_name = Column(String(250),nullable=True)
    Published = Column(String(250),nullable=True)

engine = create_engine('sqlite:///feeds/IP_Report.db')      #Create an engine that stores data in the local directory, IP_Report.db file.
 
Base.metadata.create_all(engine)    #Create all tables in the engine. Equivalent to "Create table" statement in raw SQL.
