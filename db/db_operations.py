import os
from imzaci.config import INTERNAL_DB_FILE
from imzaci.util.ssl_util import open_internal_db

#here you put the certs you trust
TRUSTED_DB_PATH = "/home/makkalot/mygits/pysign/imzaci/chain/trusted"
TRUSTED_DB = "trusted"
#here you put the banned certs and theirs CA's
UNTRUSTED_DB_PATH = "/home/makkalot/mygits/pysign/imzaci/chain/untrusted"
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
        from imzaci.util.ssl_util import open_internal_db
        if not self.__db_dir or not os.path.exists(os.path.join(self.__db_dir,INTERNAL_DB_FILE)):
            print "The internal db file is corrupted or doesnt exists,you should run recreate_internal_db method"
            return False
        result = open_internal_db(self.__db_dir,"r",write_dict=None)
        if not result:
            return True
        else:
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
        
        for db_cert_hash,cert_dict in self.__cert_store.iteritems():
            if db_cert_hash == cert_hash and cert_subj==cert_dict['cert_subject']: #it seems we have that entry
                #do we have that cert file
                print "We have the cert in database already"
                return False

        if cert_file:
            cert_file = self.__generate_filename(cert_file)

        else:
            #a default entry
            cert_file = self.__generate_filename("cert")
            
        cert_entry = self.__create_entry_index(cert_obj,os.path.split(cert_file)[1],is_chain=False)
        open_internal_db(self.__db_dir,"w",write_dict=cert_entry)
        cert_obj.store_to_file(cert_file)
        return True

    
    def add_cert_chain(self,cert_chain_obj):
        """
        Adds a chain into the db
        first check if it is a valid chain
        and also check if you have the exact chain into the db
        """
        pass

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
        """
        pass

    def list_db_all(self):
        """
        Lists all the certs in that db (direcory actually)
        """
        self.__initialize_db_ifnot() 
        #Now just print the stuff natively
        #print self.__cert_store
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
        """
        pass

    def remove_chain(self,cert_criteria):
        """
        Removes a whole chain of certs
        """
        pass

    def clear_db(self):
        """
        A dangerous one be careful :)
        """
        pass

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
        import glob
        from imzaci.util.cert_util import parse_pem_cert 
        from imzaci.cert.chain_manager import chain_manager_factory,X509ChainManager

        internal_file_path = os.path.join(self.__db_dir,INTERNAL_DB_FILE)
        if os.path.exists(internal_file_path):
            os.remove(internal_file_path)

        possible_certs = glob.glob("".join([self.__db_dir,"/","*.pem"]))
        if not possible_certs:
            print "There s no cert file into the dir you try to create internal db ",self.__db_dir
            return False

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
                        cert_entry = self.__create_entry_index(c,cert_file,is_chain=True)
                        open_internal_db(self.__db_dir,"w",write_dict=cert_entry)
            else:
                #it is a single one
                cert_entry = self.__create_entry_index(parsed_object[0],cert_file,is_chain=False)
                open_internal_db(self.__db_dir,"w",write_dict=cert_entry)

        return True

    def check_for_errors(self):
        """
        Check if there are some corrupted or expired and report them
        """
        pass

    def clean_expired(self):
        """
        Clean the expired certs
        """
        pass

    def __create_entry_index(self,cert_obj,cert_file,is_chain=False):
        """
        Add cert properties into the internal db
        """
        from imzaci.util.ssl_util import open_internal_db
        
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
        """
        self.__initialize_db_ifnot()
        search_result = {}
        for cert_hash,cert_detail in self.__cert_store.iteritems():
            #check if cert hash matches the serach query ...
            if (cert_hash == search_criteria) or (search_criteria in extract_subject_info(cert_detail["cert_subject"])):
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
                    if c.cert_hash() == cert_hash:
                        certs.append(c)
                    else:
                        continue
        #get those certs
        return certs


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
