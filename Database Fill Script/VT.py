import vt
from pymongo import MongoClient
from time import sleep

'''Change anything below this line to fit your need'''

# File with virus hashes. Make sure every line is purely a hash
import_file = 'vs0.txt'
# You probably don't want to change this too much
# This is the number of seconds between each VT query (VT allows 4 queries a minute)
seconds = 16
# This is your Virus Total API key
api_key = "0fcd0d79fe701c6469dd6caf4314660c918057079335eaf32041a306002cf339"
# This is your MongoDB database and cluster access username
username = "Devon_S"
# This is your MongoDB database and cluster access password
password = "ZEfF3mpKAzhf5bwB"

'''Do not change anything else below this line'''


# VirusTotal API connection#
url = 'https://www.virustotal.com/api/v3/search/report'
virustotal = vt.Client(api_key)

# MongoDB API connection#
cluster = MongoClient("mongodb+srv://"+username+":"+password +
                      "@cluster0.nnvlm.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
db = cluster["hashes_db"]
collection = db["hashes"]

# File import
file = open(import_file, 'r')
lines = file.readlines()

# Append new virus hashes to MongoDB
# This loops the whole file you put in and skips hashes already in the database
for site in lines:
    site = site.strip('\n')
    if collection.find_one({"data.id": site}) != None or collection.find_one({"data.inserted_id": site}) != None:
        print(site, "found")
    else:
        post = virustotal.get_json("/files/" + site)
        print(site, "inserted")
        post["data"]["inserted_id"] = site
        collection.insert_one(post)
        sleep(seconds)

virustotal.close()
