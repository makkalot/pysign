""" Modules that signs and verifies pkcs 7 documents"""
from M2Crypto import BIO, Rand, SMIME, X509
from M2Crypto import m2

import os
from imzaci.cert.cert_tools import load_private_key,load_chain_dir
from imzaci.config import *

class Pkcs7Manager(object):
    from imzaci.digest.file_operations import DirHashHandler

    def __init__(self):
        self.sm_module = SMIME 
        self.sm=self.sm_module.SMIME()
        #That one will keep the pkcs7 document
        self.p7=None
        self.file_hash = None 
    def makebuf(self,txt):
        """ Makes a text buffer"""
        return BIO.MemoryBuffer(txt)
    
    def get_sign_hash(self,sign_dir,except_list = None):
        """
        That is an util method which gives back the final
        hash of a directory ...
        """
        from imzaci.digest.digest_util import DigestUtil
        from imzaci.digest.file_operations import DirHashHandler
        
        tmp_store_file = "tmp.txt"

        self.dir_hash = DirHashHandler(sign_dir,except_list)
        self.dir_hash.store_final_hash(tmp_store_file)
        #that is the hash of teh hashes ...
        self.file_hash = DigestUtil.digest_from_file(tmp_store_file)
        print "The final hash is ...:",self.file_hash
        #the buffer to be signed
        self.tosign_buffer=self.makebuf(self.file_hash)
        os.remove(tmp_store_file)



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

        tmp_store_cert = "tmp.pem"
        
        self.get_sign_hash(sign_dir)
        subject_cert = self.__chain.get_final_subject()
        #FIXME some stupid IO operation ...
        subject_cert.store_tofile(tmp_store_cert)
        subject_cert = tmp_store_cert

        ca_stack = self.__chain.dumpto_stack()
        #fisrly load the cert and key into smime object
        try:
            #print "The private key is :",self.__private_key
            #print "The cert is :",subject_cert

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
            self.__p7=self.sm.sign(self.tosign_buffer,flags=flagset)
            #thing i saw in the examples
            self.tosign_buffer = self.makebuf(self.file_hash)
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
            tmp_io = open(os.path.join(sign_dir,Pkcs7Verifier.DEFAULT_SIGNATURE_NAME),"w")
        else:
            tmp_io = open(signature,"w")

        tmp_io.write(out.read())
        out.close()
        tmp_io.close()
        
        os.remove(tmp_store_cert)
        #print "The file signed succesfully"

        
class Pkcs7Verifier(Pkcs7Manager):
    """
    The verifier part of the pkcs7 manager
    """
    DEFAULT_SIGNATURE_NAME = "signature.p7"
    
    def __init__(self):
        from imzaci.db.db_operations import DbCertHandler
        super(Pkcs7Verifier,self).__init__()
        self.__db_handler = DbCertHandler()
        self.__db_handler.load_db()

    def verify_document(self,verify_dir):
        """
        Verifies the directory with signature
        """
        #the part we are going to verify
        self.verify_dir = verify_dir
        self.signature_file = self.get_signature_file()
        chain = self.load_chain_sign()
        
        #now we have the chain we have the signature we have
        #all the stuff so it is time to make a db lookup ...
        chain_search_str = chain.get_chain_hash()
        ch_result = self.__db_handler.search_and_get_chain(chain_search_str)
        if not ch_result:
            raise PkcsOperationException("The chain that signed document is not in your TRUSTED_DAtABASE verify fails")
        found = False
        for ch in ch_result:
            if ch == chain:
                found = True
                break

        if not found:
            raise PkcsOperationException("The chain seems to be in database but exact match failed (are u tricking me ?)")

        #the chain passed all the tests and it is ready to be verified
        #ger a pkcs7 object from the signature
        try:
            #print "The signature file is :",self.signature_file
            self.__p7 = self.sm_module.load_pkcs7(self.signature_file)
        except Exception,e:
            print "Couldnt load the signature file intoa objecti :",e
            return
        try:
            #some boiler code
            xStore=X509.X509_Store()
            sk = X509.X509_Stack()
            self.sm.set_x509_stack(sk)
            self.sm.set_x509_store(xStore)
            
            #Sets the flags to noverify which means that the verification of
            #the signers was made above
            flagset=SMIME.PKCS7_NOVERIFY
            #verify the signature it is a M2Crypto openssl method
            #create the s,gnature firstly ...
            self.get_sign_hash(verify_dir,[self.signature_file])
            #print "What we have in the buffer now ? ",self.tosign_buffer.read()
            res=self.sm.verify(self.__p7,self.tosign_buffer,flags=flagset)
            if not res:
                print "Verification failed "
                return False
            else:
                return True
            
        except Exception,e:
            print "Pkcs Error",e
            return False
        


    def get_signature_file(self):
        """
        Will try to find the signature in the dir
        """
        import glob
        possible_signatures = glob.glob("".join([self.verify_dir,"/","*.p7"])) 
        if not possible_signatures:
            raise PkcsOperationException("There is no signature file in directory (.p7)")
        
        signature = None
        for s in possible_signatures:
            if os.path.split(s)[1] == self.DEFAULT_SIGNATURE_NAME:
                signature = s
                return signature

        #if we dont have the default we return the first we see
        return possible_signatures[0]
        
    def load_chain_sign(self):
        from imzaci.util.cert_util import parse_pem_cert_buf
        from imzaci.sign.pkcs7_util import get_cert_from_signature
        from imzaci.cert.chain_manager import X509ChainManager,chain_manager_factory
        """
        Get the certs and chains from the signature
        test if we trust em and continue verification
        """
        chain_string = get_cert_from_signature(self.signature_file)
        #print chain_string
        if not chain_string:
            raise PkcsOperationException("Error when extracting chains from sginature file ...(probably corrupted or changed)")
        chain_candidates = parse_pem_cert_buf(chain_string)
        if not chain_candidates:
            raise PkcsOperationException("Error when extracting chains from sginature file ...(probably corrupted or changed)")
       
        chain =chain_manager_factory(chain_candidates,X509ChainManager.X509_CERT) 
        if not chain:
            raise PkcsOperationException("Chain extracted from signature file, but it was not a valid chain, probably corrupted signature file")
        
        #get the chain
        return chain
        #now we have the candidates try to construct the chain from them

class PkcsOperationException(Exception):
    """
    Raised when we have some pkcs error a default one
    """
    
    def __init__(self, value=None):
        Exception.__init__(self)
        self.value = value
    def __str__(self):
        return "%s" %(self.value,)



if __name__=="__main__":
    pass

