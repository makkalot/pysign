
#here you put the certs you trust
TRUSTED_DB = "trusted"
#here you put the banned certs and theirs CA's
UNTRUSTED_DB = "untrusted"
#here you put your stuff !
MY_STORE= "mystore"

class DbCertHandler():
    """
    That class will e responsible for adding,listing,removing stuff
    in your file system db. File system db is better for our purposes
    for now ...
    """

    def __init__(self,db_dir=TRUSTED_DB):
        self.db_dir = db_dir
        

    def load_db(self):
        """
        Load the certs and chanin into the memory
        """
        pass

    def add_cert(self,cert_obj):
        """
        Adds a single cert into the database it is
        important to make the checks and see if you have it
        already there
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
        pass

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

