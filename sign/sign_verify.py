""" Modules that signs and verifies pkcs 7 documents"""
from M2Crypto import BIO, Rand, SMIME, X509
from M2Crypto import m2

from imzaci.cert.cert_tools import load_private_key,load_chain_dir

class Pkcs7Manager(object):
    from imzaci.digest.file_operations import DirHashHandler

    def __init__(self):
        self.sm=SMIME.SMIME()
        #That one will keep the pkcs7 document
        self.p7=None
        
    def makebuf(self,txt):
        """ Makes a text buffer"""
        return BIO.MemoryBuffer(txt)
    

class Pkcs7Signer(Pkcs7Manager):
    """
    The signer class here
    """
    
    def set_sign_chain(self,chain_place,private_key=None):
        """
        Sets the sign chain here is True ok otherwise there is
        a failure better check the log files ...
        chain_place is a place where you have all of your 
        chain certs and private_key that will be responsible
        for signing the data we want ...
        """
        #get the chain from file
        self.__chain = load_chain_dir(chain_place)
        if not self.__chain:
            #log some info here
            return False
        if not private_key:
            #will try to find it
            self.__private_key = load_private_key(chain_place)
        if not self.__private_key:
            return False

        return True
        #get the key from file and set them
    
    def sign_data(self,sign_dir,signature=None):
        """
        Sign the data and put it into a .p7
        file with other fellows !
        """
        from imzaci.digest.digest_util import DigestUtil
        from imzaci.digest.file_operations import DirHashHandler
        import os

        tmp_store_file = "tmp.txt"
        tmp_store_cert = "tmp.pem"

        self.dir_hash = DirHashHandler(sign_dir)
        self.dir_hash.store_final_hash(tmp_store_file)
        #that is the hash of teh hashes ...
        file_hash = DigestUtil.digest_from_file(tmp_store_file)
        print "The final hash is ...:",file_hash
        #the buffer to be signed
        tosign_buffer=self.makebuf(file_hash)
        os.remove(tmp_store_file)

        subject_cert = self.__chain.get_final_subject()
        #FIXME some stupid IO operation ...
        subject_cert.store_tofile(tmp_store_cert)
        subject_cert = tmp_store_cert

        ca_stack = self.__chain.dumpto_stack()
        #fisrly load the cert and key into smime object
        try:
            print "The private key is :",self.__private_key
            print "The cert is :",subject_cert

            self.sm.load_key(self.__private_key, subject_cert)
        except:
            print "Problem with suppplied credentials ..."
            return False

        #after loading em we should set the stack that will go with
        #that signed object
        self.sm.set_x509_stack(ca_stack)
        #set the flags 
        flagset=SMIME.PKCS7_DETACHED
        #now sign the object and creta a p7 Object
        try:
            self.__p7=self.sm.sign(tosign_buffer,flags=flagset)
            #thing i saw in the examples
            tosign_buffer = self.makebuf(file_hash)
        except SMIME_Error,e:
            print "Some error when signing"
            return False

        #after signing the stuff next step is 
        try :
            out=BIO.MemoryBuffer()
            self.__p7.write(out)
            
        except BIO.BIOError,e:
            print "Memory Error :",e
            return False

        #store_the stuff into a file ...
        if not signature:
            tmp_io = open("signed.p7","w")
        else:
            tmp_io = open(signature,"w")

        tmp_io.write(out.read())
        out.close()
        tmp_io.close()
        
        os.remove(tmp_store_cert)
        print "The file signed succesfully"

        
class Pkcs7Verifier(Pkcs7Manager):
    pass


if __name__=="__main__":
    pass

