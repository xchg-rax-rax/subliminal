import datetime
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ConfigurationError
from bson import ObjectId

class Database():
    def __init__(self, config):
        self.config = config
        self.connect_to_db()

    def connect_to_db(self):
        # Attempt to connect to the specified mongodb  instance
        try:
            if self.config.db_user:
                self.client = MongoClient(f"mongodb://{self.config.db_user}:{self.config.db_password}@{self.configdb_ip}:{self.config.db_port}/?authSource=admin")
            else:
                self.client = MongoClient(self.config.db_ip, self.config.db_port)
            self.client.admin.command('ping')
        except ConnectionFailure:
            print("[!] Failed to connect to MongoDB!")
            self.client = None
        except ConfigurationError:
            print("[!] Failed to authenticate to MongoDB!")
            self.client = None
        else:
            self.db = self.client.get_database(self.config.db_name)
            self.users = self.db.users
            self.cases = self.db.cases
            self.scans = self.db.scans
            self.artefacts = self.db.artefacts

    # User Management Methods 
    
    def create_user(self,username:str ,password_hash:str) -> ObjectId:
        user = {"username":username, "password":password_hash, "cases":[]}
        try:
            user_id = self.users.insert_one(user).inserted_id
            print("[*] Created user.")
            return user_id
        except Exception as e:
            print(e)
            print("[!] Failed to create user.")
            return None

    def read_user(self, username:str=None, user_id:ObjectId=None) -> dict:
        if (username and user_id) or not (username or user_id):
            raise ValueError("read_user must be called with one and only one argument.")
        elif username:
            return self.users.find_one({"username":username})
        else:
            return self.users.find_one({"_id":user_id})

    def delete_user(self, user_id) -> bool:
        """ Ask the database to delete the with the specified username."""
        try:
            self.users.delete_one({'_id':user_id})
            print(f"[*] Deleted User {user_id}.")
            return True
        except Exception as e:
            print(e)
            print(f"[!] Failed to delete user {user_id}.")
            return False

    # Case Management Methods

    def create_case(self, owner_id:ObjectId, case_name:str, tags:list[str], summary:str) -> ObjectId:
        now  = datetime.datetime.utcnow()
        case = {"case_name":case_name,"owner_id":owner_id,"tags":tags,"summary":summary,"created":now,"updated":now,"scans":[]} 
        try:
            case_id = self.cases.insert_one(case).inserted_id
            try:
                self.users.update_one({"_id":owner_id},{'$push':{'cases':case_id}})
            except Exception as e:
                # if the write to user fails, delete the case to prevent corruption of DB
                self.cases.delete_one({"_id":case_id})
                print(e)
                return None
            return case_id 
        except Exception as e:
            print(e)
            return None

    def read_case(self, case_id:ObjectId):
        return self.cases.find_one({"_id":case_id})

    def delete_case(self, case_id:ObjectId) -> bool:
        try:
            case = self.read_case(case_id)
            case_result = self.cases.delete_one({'_id':case_id})
            user_result = self.users.update_one({'_id':case['owner_id']},{'$pull':{'cases':{'$in':[case_id]}}})
            scan_results = [self.delete_scan(scan_id) for scan_id in case['scans']]
            if case_result.deleted_count > 0 and user_result.modified_count > 0 and all(scan_results):
                print(f"[*] Deleted case {case_id}.")
                return True
            else:
                raise ValueError("deleted_count for user or case was less than 1, delete failed")
                return False
        except Exception as e:
            print(e)
            print(f"[!] Failed to delete case {case_id}.")
            return False

    # Scan Management Methods

    def create_scan(self, case_id:ObjectId, scan_name:str, scan_type:int, scope:list[str], settings:dict, duplicate:int=0) -> ObjectId:
        now  = datetime.datetime.utcnow()
        scan = {"scan_name":scan_name,"case_id":case_id,"scan_type":scan_type,"scope":scope,"settings":settings,"created":now,"finished":None,"artefacts":[],"results_summary":None,'status':0,'duplicate':duplicate} 
        try:
            scan_id = self.scans.insert_one(scan).inserted_id
            try:
                self.cases.update_one({"_id":case_id},{'$push':{'scans':scan_id}})
            except Exception as e:
                # if the write to case fails, delete the scan to prevent corruption of DB
                self.scans.delete_one({"_id":scan_id})
                print(e)
                return None
            return scan_id 
        except Exception as e:
            print(e)
            return None

    def read_scan(self, scan_id:ObjectId):
        return self.scans.find_one({"_id":scan_id})

  
    def delete_scan(self, scan_id:ObjectId) -> bool:
        try:
            scan = self.read_scan(scan_id)
            artefact_results = [self.delete_artefact(artefact_id) for artefact_id in scan['artefacts']]
            scan_result = self.scans.delete_one({'_id':scan_id})
            case_result = self.cases.update_one({'_id':scan['case_id']},{'$pull':{'scans':{'$in':[scan_id]}}})
                
            if scan_result.deleted_count > 0 and case_result.modified_count> 0 and all(artefact_results):
                print(f"[*] Deleted scan {scan_id}.")
                return True
            else:
                raise ValueError("deleted_count for scan, case or an artefact was less than 1, delete failed")
                return False
        except Exception as e:
            print(e)
            print(f"[!] Failed to delete scan {scan_id}.")
            return False

    def copy_scan(self, scan_id:ObjectId):
        scan = self.read_scan(scan_id)
        scan_duplicates = self.scans.find({'scan_name':scan['scan_name'],'case_id':scan['case_id']})
        max_duplicate = max([scan_duplicate['duplicate'] for scan_duplicate in scan_duplicates])
        return self.create_scan(scan['case_id'], scan['scan_name'], scan['scan_type'], scan['scope'], scan['settings'], duplicate=max_duplicate+1)
    
    def is_scan_name_unique(self, scan_name:str, case_id:ObjectId):
        result = self.scans.find({'scan_name':scan_name,'case_id':case_id})
        return False if result.count() > 0 else True

    def scan_set_status(self, scan_id:ObjectId, status:int):
        self.scans.update_one({'_id':scan_id},{'$set':{'status':status}}) 
        
    # Artefact Management Methods

    def create_artefact(self, scan_id:ObjectId, artefact_type:str, raw_content=None, parsed_content:dict=None) -> ObjectId:
        now  = datetime.datetime.utcnow()
        artefact = {"scan_id":scan_id,"artefact_type":artefact_type,"raw_content":raw_content,"parsed_content":parsed_content,"created":now} 
        try:
            artefact_id = self.artefacts.insert_one(artefact).inserted_id
            try:
                self.scans.update_one({"_id":scan_id},{'$push':{'artefacts':artefact_id}})
            except Exception as e:
                # if the write to case fails, delete the artefact to prevent corruption of DB
                self.artefacts.delete_one({"_id":artefact_id})
                print(e)
                return None
            return artefact_id 
        except Exception as e:
            print(e)
            return None

    def read_artefact(self, artefact_id:ObjectId):
        return self.artefacts.find_one({"_id":artefact_id})

      
    def delete_artefact(self, artefact_id:ObjectId) -> bool:
        try:
            artefact = self.read_artefact(artefact_id)
            artefact_result = self.artefacts.delete_one({'_id':artefact_id})
            scan_result = self.scans.update_one({'_id':artefact['scan_id']},{'$pull':{'artefacts':{'$in':[artefact_id]}}})
            if artefact_result.deleted_count > 0 and scan_result.modified_count > 0:
                print(f"[*] Deleted artefact {artefact_id}.")
                return True
            else:
                raise ValueError("deleted_count for artefact or scan was less than 1, delete failed")
                return False
        except Exception as e:
            print(e)
            print(f"[!] Failed to delete artefact {artefact_id}.")
            return False

