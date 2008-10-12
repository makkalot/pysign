import os
from imzaci.config import INTERNAL_DB_FILE,TRUSTED_DB_PATH,UNTRUSTED_DB_PATH
from imzaci.db.index_db import get_index_data,write_index_data,delete_index_data
import glob
#here you put the certs you trust
TRUSTED_DB = "trusted"
#here you put the banned certs and theirs CA's
UNTRUSTED_DB = "untrusted"
#here you put your stuff !
MY_STORE= "mystore"

class DbCertHandler(object):
    """
    That class will e responsible for adding,listing,removing stuff
    in your file system db. File system db is better for our purposes
    for now ...
    """

    def __init__(self,db_dir=TRUSTED_DB):
        if db_dir == TRUSTED_DB:
            self.__db_dir = TRUSTED_DB_PATH
        elif db_dir == UNTRUSTED_DB:
            self.__db_dir = UNTRUSTED_DB_PATH
        else:
            #you may want to do it explicitly ...
            self.__db_dir = db_dir

        #The internal db file will be loaded in that structure
        self.__cert_store = None
            
        

    def load_db(self):
        """
        Load the certs and chain into the memory
        actually we load the index file with summary of 
        the certs
        """
        if not self.__db_dir or not os.path.exists(os.path.join(self.__db_dir,INTERNAL_DB_FILE)):
            #Make here a logger plzzz
            #print "The internal db file is corrupted or doesnt exists,you should run recreate_internal_db method"
            return False
        result = get_index_data(self.__db_dir)
        self.__cert_store = result
        return True

    

    def add_cert(self,cert_obj,cert_file=None):
        """
        Adds a single cert into the database it is
        important to make the checks and see if you have it
        already there ...
        """
        #some sanity checks ...
        self.__initialize_db_ifnot()
        
        cert_subj = cert_obj.person_info()
        cert_hash = cert_obj.cert_hash()
        
        #firstly make a search for that cert in db wanto go deepr ?
        cert_result = self.search_and_get_cert(cert_hash)
        if cert_result:
            for cert in cert_result:
                #we can compare two cert you know :)
                if cert == cert_obj:
                    print "The cert you are trying to add already exists into db"
                    return False

        if cert_file:
            cert_file = self.__generate_filename(cert_file)
        else:
            #a default entry
            cert_file = self.__generate_filename("cert")
            
        cert_entry = self.__create_entry_index(cert_obj,cert_file,is_chain=False)
        write_index_data(self.__db_dir,cert_entry)
        cert_obj.store_to_file(cert_file)
        #reload the stuff
        self.load_db()
        return True

    
    def add_cert_chain(self,cert_chain_obj,chain_file = None):
        """
        Adds a chain into the db
        first check if it is a valid chain
        and also check if you have the exact chain into the db
        """
        
        #firstly make a search 
        compare_chains = self.search_and_get_chain("*") #get all chains
        if compare_chains: #look insite em and search for a match
            for chain in compare_chains:
                if chain == cert_chain_obj:
                    print "The chain you try to insert into db already exists"
                    return False
                
        if chain_file:
            chain_file = self.__generate_filename(chain_file)
        else:
            #a default entry
            chain_file = self.__generate_filename("chain")
        
        #add one by one to the index file
        for cert_store in cert_chain_obj:
            cert_entry = self.__create_entry_index(cert_store,chain_file,is_chain=True,chain_hash=cert_chain_obj.get_chain_hash())
            write_index_data(self.__db_dir,cert_entry) 
        #store the file into a chain file
        cert_chain_obj.store_to_file(chain_file)
        #reload the stuff
        self.load_db()
        return True



    def add_cert_from_file(self,path):
        """
        Passes the cert to the add_cert method actually !
        """
        from M2Crypto import X509 as x
        from imzaci.cert.cert import X509Cert

        if not os.path.exists(path):
            print "No cert to add into database"
            return False

        cert=x.load_cert(path)
        cert_obj=X509Cert(cert)
        filename = os.path.split(path)[1]
        if self.add_cert(cert_obj,filename):
            return True
        else:
            return False

    def add_chain_from_file(self,path):
        """
        Passes the chain to the add_cert_chain method
        a very useful method ...
        """
        from imzaci.cert.cert_tools import load_chain_file
        chain_obj=load_chain_file(path)
        if not chain_obj:
            return False
        
        if not self.add_cert_chain(chain_obj,os.path.split(path)[1]):
            return False
        return True

    def list_db_all(self):
        """
        Lists all the certs in that db (direcory actually)
        """
        self.__initialize_db_ifnot() 
        #Now just print the stuff natively
        #print self.__cert_store
        if self.__cert_store is None:
            print "No items in database ...!"
            return

        print "|Cert hash| \t |Cert Detail|"
        for cert_hash,cert_detail in self.__cert_store.iteritems():
            print cert_hash
            print cert_detail

    def list_chain_certs(self,by_hash=None,by_sub_name=None):
        """
        Lists the certs into chain by given any hash of any of the
        certs or by given the subject name of any of the certs
        """
        pass

    def list_cert_detail(self,search_criteria,summary=False):
        """
        Lists the certs detailed info for given criteria
        The criteria can be hash,subject_name or
        issuer_name
        summary is for printing the raw cert or a summary
        """
        if summary:
            search_result = self.search_cert(search_criteria)
            if not search_result:
                return []
            print "|Cert hash| \t |Cert Detail|"
            for cert_hash,cert_detail in search_result.iteritems():
                print "***************************"
                print cert_hash
                print cert_detail
                print "***************************"
            
        else:
            search_result = self.search_and_get_cert(search_criteria)
            if not search_result:
                return []
            for s in search_result:
                print "***************************"
                print s
                print "***************************"

    def remove_cert(self,cert_criteria):
        """
        Removes all the certs that match the criteria
        It is a litlle bit tricky because if the cert_criteria
        matches some of the cert chain we have to remove all the 
        chain so we should be careful about that,when using the method !
        """
        remove_list = self.search_cert(cert_criteria)
        #print "**********The remove list is :**********",remove_list
        if not remove_list:
            print "No cert matches to be removed"
            return False
        
        removed_chain_files = set()
        final_remove_index = []
        try:
            for rem_cert_hash,rem_cert_pack in remove_list.iteritems():
                #if it is a chain and we didnt remove it already ...
                if rem_cert_pack['is_chain'] and not rem_cert_pack['cert_file'] in removed_chain_files:
                    #we should remove all the certs in that chain
                    removed_chain_files.add(rem_cert_pack['cert_file'])
                    os.remove(rem_cert_pack['cert_file'])
                
                else:
                    #remove that cert only
                    #print "Removing that file :",rem_cert_pack['cert_file']
                    os.remove(rem_cert_pack['cert_file'])
                    
                final_remove_index.append(rem_cert_hash)
            
            #remove the final hashes from index db
            delete_index_data(self.__db_dir,final_remove_index)
            #reload the index again if you are going to reuse that object
            self.load_db()
        except Exception,e:
            print e
            return False
        
        return True

                
    def remove_chain(self,chain_criteria):
        """
        Removes a whole chain of certs it gets
        the list of files and removes em
        """
        chain_remove_list = self.search_chain(chain_criteria)
        if not chain_remove_list:
            return False

        for chain_file in chain_remove_list:
            os.remove(chain_file)
            #load the db again
    
        #reload all the stuff
        self.recreate_internal_db()
        #get it into the memory
        self.load_db()
        return True
            



    def clear_db(self):
        """
        A dangerous one be careful :)
        """
        
        internal_file_path = os.path.join(self.__db_dir,INTERNAL_DB_FILE)
        if os.path.exists(internal_file_path):
            index_files = glob.glob("".join([internal_file_path,"*"]))
            #print "The index files to remove : ",index_files
            for index_file in index_files:
                os.remove(index_file)

        possible_remove_certs = glob.glob("".join([self.__db_dir,"/","*.pem"]))
        for r_cert in possible_remove_certs:
            os.remove(r_cert)
        return True

    def recreate_internal_db(self):
        """
        Recreating the internal db because it is corrupted
        or not exists .The internal structure for every cert will be like :
        
            'cert_hash':{
                'cert_subject':"value of the subject",
                'cert_file':"value of the file name",
                'chain':True,False
            }
            
        """
        from imzaci.util.cert_util import parse_pem_cert 
        from imzaci.cert.chain_manager import chain_manager_factory,X509ChainManager

        internal_file_path = os.path.join(self.__db_dir,INTERNAL_DB_FILE)
        if os.path.exists(internal_file_path):
            index_files = glob.glob("".join([internal_file_path,"*"]))
            #print "The index files to remove : ",index_files
            for index_file in index_files:
                os.remove(index_file)

        possible_certs = glob.glob("".join([self.__db_dir,"/","*.pem"]))
        if not possible_certs:
            write_index_data(self.__db_dir,{})
            return True

        for cert_file in possible_certs:
            parsed_object = parse_pem_cert(cert_file)
            if not parsed_object:
                continue

            if len(parsed_object)>1:#it may be a chain
                chain = chain_manager_factory(parsed_object,X509ChainManager.X509_CERT)
                if not chain:#it seems we dont have a valid chain here
                    continue
                else:
                    for c in chain:
                        cert_entry = self.__create_entry_index(c,cert_file,is_chain=True,chain_hash=chain.get_chain_hash())
                        write_index_data(self.__db_dir,cert_entry)
            else:
                #it is a single one
                cert_entry = self.__create_entry_index(parsed_object[0],cert_file,is_chain=False)
                write_index_data(self.__db_dir,cert_entry)
        return True

    def check_for_errors(self):
        """
        Check if there are some corrupted or expired and report them
        That is a simple test which controls if the indexdb matches
        the files system and also checks for expired things into db
        thats all no magic here :)
        """
        from imzaci.cert.cert_tools import load_chain_file
        #some initial
        self.__initialize_db_ifnot()
        is_error = False
        #we may not have any certs here 
        if not self.__cert_store:
            return False

        #check for indexdb-filedb match
        checked_chain_files = set()
        for cert_hash,cert_pack in self.__cert_store.iteritems():
            cert_obj = self.search_and_get_cert(cert_hash)
            if not cert_obj:
                #here will be also logging
                print "There is an entry for %s:%s cert in index db but you dont have it on fs"%(cert_hash,cert_pack['cert_file'])
                is_error = True
            else:
                cert_obj = cert_obj[0]
                if not cert_hash == cert_obj.cert_hash():
                    print "There is an entry for %s:%s cert in index db but you dont have it on fs (hash mismatch)"%(cert_hash,os.path.split(cert_pack['cert_file'])[1])
                    is_error = True
                if not cert_obj.is_valid():
                    print "The cert with subject:%s is invalid(expired) "%(cert_obj.person_info())
                    is_error = True
                if not cert_pack['cert_subject'] == cert_obj.person_info():
                    print "There is an entry for %s:%s cert in index db but you dont have it on fs (subject mismatch)"%(cert_hash,os.path.split(cert_pack['cert_file'])[1])
                    is_error = True

                #check for cert chains if we didnt break sth
                if cert_pack['is_chain']:
                    print cert_pack['cert_file']
                    if not cert_pack['cert_file'] in checked_chain_files:
                        checked_chain_files.add(cert_pack['cert_file'])
                        result = load_chain_file(cert_pack['cert_file'])
                        #print result
                        if not result:
                            print "Error when loading chain file %s probably you have broken sth"%(os.path.split(cert_pack['cert_file'])(1))
                            is_error = True
        if is_error:
            print "Try re running the recreate_internal_db method and clean_expired methods"
            return True
        #means there is no errors

        #print "All stuff is ok"
        return False
    def clean_expired(self):
        """
        ***Clean the expired certs****
        """
        all_certs = self.search_and_get_cert("*")
        if not all_certs:
            return True

        for cert in all_certs:
            if not cert.is_valid():
                #remove the cert with matching hash
                self.remove_cert(cert.cert_hash())

        return True

    def __create_entry_index(self,cert_obj,cert_file,is_chain=False,chain_hash=None):
        """
        Add cert properties into the internal db
        """
        if is_chain and chain_hash: 
            #if it is a chain its hash is in chain_hash-cert_hash
            #we need it that way because when have similar chains we
            #may miss some of the certs because they will have the same
            #hashes in it 
            cert_hash = "".join([chain_hash,"-",cert_obj.cert_hash()])
        else:
            #for normal certs we use its real hash in that case
            cert_hash = cert_obj.cert_hash()
        cert_subject = cert_obj.person_info()
        is_chain = is_chain
        cert_file = cert_file
        
        return {
                cert_hash:{
                    'cert_subject':cert_subject,
                    'cert_file':cert_file,
                    'is_chain':is_chain
                    }
                }

    def __generate_filename(self,possible_name):
        """
        An util method for generatign cert names
        """
        import string
        nth_item = 1
        while os.path.exists(os.path.join(self.__db_dir,possible_name)):
            
            if string.find(possible_name,".pem") != -1:
                possible_name = possible_name.split(".pem")[0]
            
            possible_name = "".join([possible_name,"_",str(nth_item),".pem"])
            nth_item +=1

        return os.path.join(self.__db_dir,possible_name)

    def search_cert(self,search_criteria):
        """
        It searches for certs and gets the results in a list
        The search_criteria can be one of the fingerprint,any field
        of the subject field in the X.509 cert
        Note: there is a shortcut "*" for getting all the certs
        """
        self.__initialize_db_ifnot()
        if search_criteria == "*":
            return self.__cert_store

        search_result = {}
        for cert_hash,cert_detail in self.__cert_store.iteritems():
            #check if cert hash matches the serach query ...
            if (cert_hash == search_criteria) or (search_criteria in extract_subject_info(cert_detail["cert_subject"])):
                search_result[cert_hash]=cert_detail
            #checkout if it is a chain_thing
            #you know the chains are in chain_hash-cert_hash format
            chain_hash = cert_hash.split("-")
            if len(chain_hash)>1 and chain_hash[1] == search_criteria:
                search_result[cert_hash]=cert_detail
            elif len(chain_hash)>1 and chain_hash[0] == search_criteria:
                search_result[cert_hash]=cert_detail


        
        return search_result


    def search_and_get_cert(self,search_criteria):
        """
        That one returns back the instances to be compared
        """
        certs=[]
        search_result = self.search_cert(search_criteria)
        if not search_result:
            return None
        
        from M2Crypto import X509 as x
        from imzaci.cert.cert import X509Cert
        from imzaci.cert.cert_tools import load_chain_file
       
        for cert_hash,cert_detail in search_result.iteritems():
            if not os.path.exists(cert_detail['cert_file']):
                print "The db is probably corrupted ,try running recreate_internal_db"
                return None
            if not cert_detail["is_chain"]:
                #if it is not a chain file you just go and get
                #the whole file so no problem here
                cert=x.load_cert(cert_detail["cert_file"])
                certs.append(X509Cert(cert))
            else:
                #the cert you are looking for is a member of a chain
                #so get it,load the chain and then look for hash match
                chain=load_chain_file(cert_detail['cert_file'])
                if not chain:
                    continue
                #is it what we look for ?
                for c in chain:
                    if c.cert_hash() == self.__get_real_hash(cert_hash):
                        certs.append(c)
                    else:
                        continue
        #get those certs
        return certs

    def __get_real_hash(self,hash_str):
        """
        Because we use chain_hash:cert_hash format
        for the index_db indexes we sometimes need
        to extract the cert_hash from that ids
        that simple util methods is for that purpose
        """
        if not hash_str:
            return ""

        chain_str = hash_str.split("-")
        if len(chain_str)>1:
            return chain_str[1]
        else:
            return ""


    def search_chain(self,search_criteria):
        """
        Searches for a chain into the database
        what we will have here as a result is a
        list of files that includes these chains
        """
        chain_files = set()
        certs=self.search_cert(search_criteria)
        if not certs:
            return None
        for cert_hash,cert_detail in certs.iteritems():
            #if it is a reak chain 
            if cert_detail['is_chain']:
                chain_files.add(cert_detail['cert_file'])
        #get the list of chain files ...
        return chain_files
    
    def search_and_get_chain(self,search_criteria):
        """
        Searches and gets the chain from the db the search_criteria
        is the same as aboves
        """
        from imzaci.cert.cert_tools import load_chain_file
        
        chain_list = []
        chain_files = self.search_chain(search_criteria)
        if not chain_files:
            return chain_list

        #we have now the chain list files so can get em
        for chain_file in chain_files:
            tmp_chain=load_chain_file(chain_file)
            if not tmp_chain:
                continue
            else:
                chain_list.append(tmp_chain)
        
        return chain_list



    def __initialize_db_ifnot(self):
        """
        An util method for controlling the 
        db initial values ...
        """
        if not self.__cert_store:
            if not self.load_db():
                self.recreate_internal_db()


    def get_current_memory_snap(self):
        """
        Gets back a dict of current indexdb
        """
        self.__initialize_db_ifnot()
        return self.__cert_store

def extract_subject_info(subject_str):
    """
    A simple util method for extracting some info
    from the subject cert string
    """
    result_str = []
    subject_str = subject_str.split("/")
    if not subject_str:
        return []

    for subject_entry in subject_str:
        if subject_entry:
            sub_value = subject_entry.split("=")
            if sub_value and len(sub_value) == 2:
                result_str.append(sub_value[1].strip())
            else:
                continue

    return result_str


if __name__ == "__main__":
    pass
