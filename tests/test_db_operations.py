#The test case for DB operations ,testing is good
from imzaci.tests.test_chain_manager import list_of_cert_dirs,do_chain_pack_exist
from imzaci.db.db_operations import DbCertHandler,extract_subject_info
#We will have some names for the testing certs

EXPIRED_CERTS = {
        "0":"/home/makkalot/code_repo/my_git/pysign/imzaci/chain/expired/cert2.pem",
        "2":"/home/makkalot/code_repo/my_git/pysign/imzaci/chain/expired/cacert.pem",
        "1":"/home/makkalot/code_repo/my_git/pysign/imzaci/chain/expired/cert1.pem"
 
        }

class TestDbCertHandler(object):
    def __init__(self):
        """
        Just create the objec that wil handle all the stuff
        """
        self.db_handler = DbCertHandler() #will use the default 

    def setUp(self):
        """
        Will be called on every initialization
        """
        self.db_handler.clear_db() #remove all the stuff
        self.db_handler.recreate_internal_db() #recreate the stuff
        self.db_handler.load_db() #load into the memory 


    def test_load_db(self):
        """
        Does it load the stuff
        """
        current_db = self.db_handler.get_current_memory_snap()
        assert  current_db=={}

    def test_add_cert(self):
        """
        Add cert object into db
        """
        from imzaci.cert.cert_tools import load_cert_from_dir
        #add one into the empty db
        cert_to_add = load_cert_from_dir(list_of_cert_dirs['0'])
        assert self.db_handler.add_cert(cert_to_add) == True
        #should check if we have that in db
        tmp_cert=self.db_handler.search_and_get_cert(cert_to_add.cert_hash())
        assert len(tmp_cert) == 1
        assert tmp_cert[0] == cert_to_add

        #add one duplicate
        assert self.db_handler.add_cert(cert_to_add) == False

        #add another when have others
        another_cert = load_cert_from_dir(list_of_cert_dirs['1'])
        assert self.db_handler.add_cert(another_cert) == True
 
        #is it there?
        tmp_cert=self.db_handler.search_and_get_cert(another_cert.cert_hash())
        assert len(tmp_cert) == 1
        assert tmp_cert[0] == another_cert


    def test_add_cert_chain(self):
        """
        Add chain object into db
        """
        from imzaci.cert.cert_tools import load_chain_from_dirs

        #add into an empty stuff
        chain_to_add = load_chain_from_dirs([list_of_cert_dirs['3'],list_of_cert_dirs['2']])
        assert self.db_handler.add_cert_chain(chain_to_add) == True
        #look if it is inside it ?
        tmp_search=self.db_handler.search_and_get_chain(chain_to_add.get_chain_hash())
        assert len(tmp_search)==1
        assert tmp_search[0] == chain_to_add

        #test the duplication
        assert self.db_handler.add_cert_chain(chain_to_add) == False
        #test for similar ones but diffrent chains
        chain_to_add = load_chain_from_dirs([list_of_cert_dirs['3'],list_of_cert_dirs['2'],list_of_cert_dirs['1']])
        assert self.db_handler.add_cert_chain(chain_to_add) == True
        #is it inside it ?
        tmp_search=self.db_handler.search_and_get_chain(chain_to_add.get_chain_hash())
        assert len(tmp_search)==1
        assert tmp_search[0] == chain_to_add

        assert self.db_handler.add_cert_chain(chain_to_add) == False    
        #print self.db_handler.get_current_memory_snap()
        

    def test_add_cert_from_file(self):
        """
        Add cert from file 
        """
        from imzaci.cert.cert_tools import load_cert_from_dir
        #add one into the empty db
        cert_to_add = load_cert_from_dir(list_of_cert_dirs['0'])
        cert_to_add.store_to_file("foo.pem")
        assert self.db_handler.add_cert_from_file("foo.pem") == True
        assert self.db_handler.add_cert_from_file("foo.pem") == False

        import os
        os.remove("foo.pem")

    def test_add_chain_from_file(self):
        """
        Add chain from file
        """
        from imzaci.cert.cert_tools import load_chain_from_dirs

        #add into an empty stuff
        chain_to_add = load_chain_from_dirs([list_of_cert_dirs['3'],list_of_cert_dirs['2']])
        chain_to_add.store_to_file("foo.pem")
        assert self.db_handler.add_chain_from_file("foo.pem") == True
        assert self.db_handler.add_chain_from_file("foo.pem") == False
        
        import os
        os.remove("foo.pem")


    def test_list_db_all(self):
        pass

    def test_list_cert_detail(self):
        pass

    def test_remove_cert(self):
        """
        Remove a cert from db
        """
        #first try to remove a cert that is not there
        assert self.db_handler.remove_cert("foo_cert")==False
        
        from imzaci.cert.cert_tools import load_cert_from_dir
        #add one into the empty db
        cert_to_add = load_cert_from_dir(list_of_cert_dirs['0'])
        self.db_handler.add_cert(cert_to_add) == True
        
        #now remove that cert from there
        assert self.db_handler.remove_cert(cert_to_add.cert_hash())==True
  
        #now search for it into db
        tmp_cert=self.db_handler.search_and_get_cert(cert_to_add.cert_hash())
        assert tmp_cert == None

    
    def test_remove_chain(self):
        """
        Remove a chain from db
        """
        #first try to remove sth is not there
        assert self.db_handler.remove_chain("foo_chain") == False

        from imzaci.cert.cert_tools import load_chain_from_dirs
        #add into an empty stuff
        chain_to_add = load_chain_from_dirs([list_of_cert_dirs['3'],list_of_cert_dirs['2']])
        self.db_handler.add_cert_chain(chain_to_add)
        
        #now remove it
        assert self.db_handler.remove_chain(chain_to_add.get_chain_hash()) == True
        #look if it is inside it ?
        tmp_search=self.db_handler.search_and_get_chain(chain_to_add.get_chain_hash())
        assert tmp_search==[]

    def test_clear_db(self):
        pass

    def test_recreate_internal_db(self):
        pass

    def test_check_for_errors(self):
        pass

    def test_clean_expired(self):
        """
        Clean expired certs
        """
        from imzaci.cert.cert_tools import load_cert_from_dir
        from M2Crypto import X509 as x
        from imzaci.cert.cert import X509Cert

        #add one into the empty db
        cert_to_add = x.load_cert(EXPIRED_CERTS['0'])
        cert_to_add=X509Cert(cert_to_add)

        self.db_handler.add_cert(cert_to_add)
        #clear the expired certs
        self.db_handler.clean_expired()
        assert self.db_handler.get_current_memory_snap() == {}

    def test_search_cert_and_get_cert(self):
        """
        Test the search operations for search_and_get_cert and search_cert
        """
        #search an empty db
        tmp_result = self.db_handler.search_cert("*")
        tmp_cert_result = self.db_handler.search_and_get_cert("*")
        assert tmp_result == {}
        assert tmp_cert_result == None
        #search emtry db for sth that is not there
        tmp_result = self.db_handler.search_cert("foo_cert")
        tmp_cert_result = self.db_handler.search_and_get_cert("foo_cert")
        assert tmp_cert_result == None
        assert tmp_result == {}
        #add a cert and search for it

        from imzaci.cert.cert_tools import load_cert_from_dir
        #add one into the empty db
        cert_to_add = load_cert_from_dir(list_of_cert_dirs['0'])
        self.db_handler.add_cert(cert_to_add)
        search_fields = extract_subject_info(cert_to_add.person_info())
        #search for every field it has ...
        for search_item in search_fields:
            tmp_result = self.db_handler.search_cert(search_item)
            tmp_cert_result = self.db_handler.search_and_get_cert(search_item)
            #check instance
            assert len(tmp_cert_result) == 1
            assert tmp_cert_result[0] == cert_to_add
            #check dict
            assert len(tmp_result.keys()) == 1
            assert tmp_result.has_key(cert_to_add.cert_hash())== True
        
        #search also the hash
        tmp_result = self.db_handler.search_cert(cert_to_add.cert_hash())
        assert len(tmp_result.keys()) == 1
        assert tmp_result.has_key(cert_to_add.cert_hash())== True

        #now make a full search again
        tmp_result = self.db_handler.search_cert("*")
        tmp_cert_result = self.db_handler.search_and_get_cert("*")

        #check instance
        assert len(tmp_cert_result) == 1
        #check the dict
        assert len(tmp_result.keys()) == 1

        tmp_cert_result = self.db_handler.search_and_get_cert("foo_cert")
        tmp_result = self.db_handler.search_cert("foo_cert")
        assert tmp_cert_result == None
        assert tmp_result == {}

        #add also a chain and make search for it
        from imzaci.cert.cert_tools import load_chain_from_dirs
        #add into an empty stuff
        chain_to_add = load_chain_from_dirs([list_of_cert_dirs['3'],list_of_cert_dirs['2'],list_of_cert_dirs['1']])
        self.db_handler.add_cert_chain(chain_to_add)
        #search for the chain hash firstly
        tmp_result = self.db_handler.search_cert(chain_to_add.get_chain_hash())
        tmp_cert_result = self.db_handler.search_and_get_cert(chain_to_add.get_chain_hash())
        assert len(tmp_result) == 3
        for cert_search in chain_to_add:
            assert tmp_result.has_key("".join([chain_to_add.get_chain_hash(),"-",cert_search.cert_hash()])) == True
            #also search for the cert in the chain 
            tmp_result_inner = self.db_handler.search_cert(cert_search.cert_hash())
            assert len(tmp_result_inner.keys()) == 1
            #print tmp_result_inner
            assert tmp_result_inner.has_key("".join([chain_to_add.get_chain_hash(),"-",cert_search.cert_hash()]))== True



    def test_search_and_get_chain(self):
        """
        Test searching and getting chain
        """
        #search in empty stuff
        tmp_chain_result=self.db_handler.search_and_get_chain("*")
        assert tmp_chain_result == []
        self.db_handler.search_and_get_chain("foo_chain")
        assert tmp_chain_result == []

        #add a chain and serach for it :)
        from imzaci.cert.cert_tools import load_chain_from_dirs
        #add into an empty stuff
        chain_to_add = load_chain_from_dirs([list_of_cert_dirs['3'],list_of_cert_dirs['2'],list_of_cert_dirs['1']])
        self.db_handler.add_cert_chain(chain_to_add)
        chain_tmp_result = self.db_handler.search_and_get_chain(chain_to_add.get_chain_hash())
        assert len(chain_tmp_result) == 1
        assert chain_tmp_result[0] == chain_to_add

        #add another similar to see can it pull the excat one from there
        another_chain_add = load_chain_from_dirs([list_of_cert_dirs['3'],list_of_cert_dirs['2']])
        self.db_handler.add_cert_chain(another_chain_add)
        chain_tmp_result = self.db_handler.search_and_get_chain(another_chain_add.get_chain_hash())
        assert len(chain_tmp_result) == 1
        assert chain_tmp_result[0] == another_chain_add



