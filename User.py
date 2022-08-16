from pymongo import MongoClient
import json
import traceback

class User(object):
    def __init__(self):
        with open("config.json", 'r') as f:
            data = json.load(f)
        username = data['MONGOUSER']
        password = data['MONGOPASS']
        cluster = MongoClient("mongodb+srv://"+username+":"+password +"@cluster0.nnvlm.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")
        db = cluster["users_db"]
        self.collection = db["users"]

    def get_user(self,username):
        return self.collection.find_one({"username":username})
    
    def insert_search(self, username, hash):
        user = self.collection.find_one({"username":username})
        if user is not None:
            recent_searches = list(user["recent_searches"])
            if len(list(user["recent_searches"])) > 4:
                try:
                    recent_searches.pop(0)
                    recent_searches.append(hash)
                    self.collection.update_one({"username":username},
                    {"$set":{"recent_searches":recent_searches}})
                except Exception:
                    traceback.print_exc()
                    return None
            else:
                try:
                    self.collection.update_one({'username':username},
                    {'$push': {"recent_searches":str(hash)}})
                except Exception:
                    print(f"Name: {username}\n Hash:{hash}\n Recent Searches: {recent_searches}")
                    traceback.print_exc()
                    return None
            return True

    def get_history(self, username):
        user = self.collection.find_one({"username":username})
        history = [i for i in user["recent_searches"] if i]
        return history


    def update_time(self, username, time):
        return self.collection.update_one({'username':username}, {"$set": {"last_accessed":(float(time))}})

    def create_user(self, username, password, time):
        self.collection.insert_one({'username':username,
                                    'password':password,
                                    'recent_searches':[None],
                                    'last_accessed':float(time)})
        return self.collection.find_one({'username':username})
