# Metadefender Core 
Query a file, hash, or IP and store the data in a local SQL Database using the OPSWAT Metadefender Core API
https://www.metadefender.com/public-api#!/about

# How to Use
## feed_collect.py
 This simple script will pull the top 1,000 new malware hash signatures, including MD5, SHA1, and SHA256 from the metadefender site. These new malicious hashes have been spotted on the networks of Metadefender Cloud users within the last 24 hours. It then stores this data in a file named 'live_feed-<CURRENT_TIME>'. This would allow for the creation of a database for an entire day so that if a new malicious file appeared on your site at the end of the day, but was only on the feed at 8am, it would still get stopped. <br>
`python feed_collect.py` 

## query_metadefender.py
This will allow you to query the Metadefender Core API with an IP address (more capabilities being added) and will return to you any categorizations that were reported in the JSON output. The Raw JSON output is saved to <IP_ADDRESS>.json should one need access to it at a later point. It can be used as follows: <br>
` python query_metadefender.py -i 103.212.204.91` 


# What's Next
Storing all of these results in a database is next. Separation of all hashes (MD5,SHA1, SHA256) into 3 tables would also speed up checking against these for live threats. 
    <h1>BIggest HEader</h1>
