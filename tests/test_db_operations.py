#The test case for DB operations ,testing is good
from imzaci.tests.test_chain_manager import list_of_cert_dirs,do_chain_pack_exist
from imzaci.db.db_operations import DbCertHandler
#We will have some names for the testing certs

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

 
