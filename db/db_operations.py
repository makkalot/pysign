import os
from imzaci.config import INTERNAL_DB_FILE

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
        

    def add_cert(self,cert_obj):
        """
        Adds a single cert into the database it is
        important to make the checks and see if you have it
        already there ...
        """
        pass

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
        pass

    def add_chain_from_file(self,path):
        """
        Passes the chain to the add_cert_chain method
        """
        pass

    def list_db_all(self):
        """
        Lists all the certs in that db (direcory actually)
        """
        if not self.__cert_store:
            self.load_db()
        
        #Now just print the stuff natively
        print self.__cert_store

    def list_chain_certs(self,by_hash=None,by_sub_name=None):
        """
        Lists the certs into chain by given any hash of any of the
        certs or by given the subject name of any of the certs
        """
        pass

    def list_cert_detail(self,cert_criteria):
        """
        Lists the certs detailed info for given criteria
        The criteria can be hash,subject_name or
        issuer_name 
        NOTE : can return more than one ! only hash gives
        back one cert detail ...
        """
        pass

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
        from imzaci.util.ssl_util import open_internal_db

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
                        cert_entry = self.__create_entry_index(c,internal_file_path,cert_file,is_chain=True)
                        open_internal_db(self.__db_dir,"w",write_dict=cert_entry)
            else:
                #it is a single one
                cert_entry = self.__create_entry_index(parsed_object[0],internal_file_path,cert_file,is_chain=False)
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

    def __create_entry_index(self,cert_obj,db_file_path,cert_file,is_chain=False):
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

if __name__ == "__main__":
    pass
