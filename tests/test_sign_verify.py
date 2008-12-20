from imzaci.sign.sign_verify import *
SIGN_DIRECTORY = "/home/makkalot/code_repo/my_git/pysign/imzaci/chain/signer"
TO_SIGN = "/home/makkalot/Desktop/gelinlik"


class TestPksc7Manager(object):
    
    fname = None

    def sign(self):
        
        import os
        print "Signing the : ",TO_SIGN
        if os.path.exists(os.path.join(TO_SIGN,Pkcs7Verifier.DEFAULT_SIGNATURE_NAME)):
            os.remove(os.path.join(TO_SIGN,Pkcs7Verifier.DEFAULT_SIGNATURE_NAME))
        
        p7_manager = Pkcs7Signer()
        p7_manager.set_sign_chain(SIGN_DIRECTORY)
        p7_manager.sign_data(TO_SIGN)
    
    def verify(self):
        print "Verify the : ",TO_SIGN
        p7_manager = Pkcs7Verifier()
        return p7_manager.verify_document(TO_SIGN)
   
    def create_dummy_file(self):
        text_to_store = "Dummy text"
        self.fname = "dummy.txt"
        io_op = open(os.path.join(TO_SIGN,self.fname),"w")
        io_op.write(text_to_store)
        io_op.close()
        

    def test_fail_remove(self):
        self.create_dummy_file()
        self.sign()
        os.remove(os.path.join(TO_SIGN,self.fname))
        assert self.verify() == False
    
    def test_fail_change(self):
        self.create_dummy_file()
        self.sign()
        io_op = open(os.path.join(TO_SIGN,self.fname),"a")
        io_op.write("add moew twxt")
        io_op.close()
        assert self.verify() == False
