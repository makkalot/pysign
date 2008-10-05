from imzaci.db.index_db import IndexDb

class TestIndexDb(object):
    """
    A simple test case for the simple index db
    """

    def __init__(self):
        self.db_dir = "trusted"

    def setUp(self):
        """
        Setter
        """
    
    def test_write_to_index(self):
        """
        test the write operation
        """
        write_me = {
                'hash':{
                    'cert_file':"hey.pem",
                    'is_chain':False,
                    'cert_subject':"subsubsub"
                    }
                }
        db = IndexDb(self.db_dir)
        assert db.write_to_index(write_me) == True
        tmp_dict = db.read_from_index()
        assert tmp_dict.has_key('hash') == True
        assert tmp_dict['hash'] == write_me['hash']


    def test_read_from_index(self):
        """
        test the read operation
        """
        #no need for that we already tested it above
        pass


    def test_delete_from_index(self):
        """
        Test the del operation
        """
        write_me = {
                'hash':{
                    'cert_file':"hey.pem",
                    'is_chain':False,
                    'cert_subject':"subsubsub"
                    },
                'del_hash':{
                    'cert_file':"del.pem",
                    'is_chain':False,
                    'cert_subject':"deldeldel"
                    }
                }
        db = IndexDb(self.db_dir)
        db.write_to_index(write_me)
        assert db.delete_from_index(["del_hash"]) == True
        tmp_dict = db.read_from_index()
        assert not tmp_dict.has_key("del_hash") == True
        assert tmp_dict.has_key('hash') == True

        #happy testing :)

       

if __name__ == "__main__":
    pass

