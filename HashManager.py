from pymongo import MongoClient
import vt
import re
import json
import traceback


class HashManager(object):
    def __init__(self):
        with open("config.json", 'r') as f:
            data = json.load(f)
        username = data['MONGOUSER']
        password = data['MONGOPASS']
        self.api_key = data['VT_API_KEY']
        self.port = data['PORT']
        cluster = MongoClient("mongodb+srv://"+username+":"+password +"@cluster0.nnvlm.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
        db = cluster["hashes_db"]
        self.collection = db["hashes"]
        self.prev_search_exists = True
        

    def search_exists(self):
        return self.prev_search_exists


    def vtquery(self, site):
        try:
            virustotal = vt.Client(self.api_key)
            post = virustotal.get_json("/files/" + site)
        except Exception:
            virustotal.close()
            traceback.print_exc()
            return -1
        virustotal.close()
        return post


    def verifyMainForm(self, form_input):
        form_input = form_input.strip()
        is_hash = re.match("|".join(["^[a-fA-F0-9]{64}$","^[a-fA-F0-9]{40}$","^[a-fA-F0-9]{32}$"]),form_input)
        if is_hash is None:
            return -2

        self.prev_search_exists = True

        sha256 = self.collection.find_one({"data.attributes.sha256": form_input})
        if sha256 is not None: return sha256

        sha1 = self.collection.find_one({"data.attributes.sha1": form_input})
        if sha1 is not None: return sha1

        md5 = self.collection.find_one({"data.attributes.md5": form_input})
        if md5 is not None: return md5


        if (sha256 == None and sha1 == None and md5 == None):
            print("new")
            self.prev_search_exists = False
            post = self.vtquery(form_input)
            if(post == -1):
                print(f'VT: {form_input} not found.')
                return post
            else:
                print("inserted")
                post["data"]["inserted_id"] = form_input
                self.collection.insert_one(post)
                return self.collection.find_one({"data.inserted_id": form_input})


    def hashpage(self, form_input):
        ip = "localhost:"+str(self.port)
        malicious_count = 0
        list_of_types = []
        total_detections = len(form_input["data"]["attributes"]["last_analysis_results"].values())
        for obj in form_input["data"]["attributes"]["last_analysis_results"].values(
        ):
            category = obj['category']
            if category == "malicious":
                malicious_count = malicious_count + 1
            list_of_types.append(category)

        list_of_names = []
        for obj in form_input["data"]["attributes"]["last_analysis_results"]:
            list_of_names.append(obj)

        total_list = []
        for i in range(0, len(list_of_names)):
            total_list.append([list_of_names[i], list_of_types[i]])

        ratio = malicious_count/total_detections

        names = form_input["data"]["attributes"]["names"]

        hash_names = {
            'sha256': form_input["data"]["attributes"]["sha256"],
            'sha1': form_input["data"]["attributes"]["sha1"],
            'md5': form_input["data"]["attributes"]["md5"],
        }
        #print(ip)
        return {"hash_names":hash_names, "names":names, "list":total_list, "total":total_detections, "mal_count":malicious_count, "ratio":ratio, "ip":ip}