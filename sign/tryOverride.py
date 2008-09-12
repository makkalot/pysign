""" Modules that signs and verifies pkcs 7 documents"""
from M2Crypto import BIO, Rand, SMIME, X509
from M2Crypto import m2


import os
import copy
import re

from cUtil import Cutil
from cert import X509Man
from stacker import stackWork
from liteDb.initializer import DbCert
from liteDb.lister import ListDb
from chainManage import chainMan
from liteDb.lister import list_chain
from digest.Hasher import DigestMan

class pkcs7Work(object):
    """Pkcs7 related work as sign documents and verify them according to pkcs7 format
    Useful Data :
    SMIME.PKCS7_DATA
    SMIME.PKCS7_DETACHED
    SMIME.PKCS7_ENVELOPED
    SMIME.PKCS7_NOATTR
    SMIME.PKCS7_NOCERTS
    SMIME.PKCS7_NOCHAIN
    SMIME.PKCS7_NOINTERN
    SMIME.PKCS7_NOSIGS
    SMIME.PKCS7_NOVERIFY
    SMIME.PKCS7_SIGNED
    SMIME.PKCS7_SIGNED_ENVELOPED
    SMIME.PKCS7_TEXT
        """
    
    def __init__(self):
        """ Initialize some basic structures"""
        
        self.sm=SMIME.SMIME()
        
        #That one will keep the pkcs7 document
        self.__p7=None
        
        
    def makebuf(self,txt):
        """ Makes a text buffer"""
        return BIO.MemoryBuffer(txt)
    
    def make_sign(self,keyplace,certplace,dataSign,signature_place):
        """ We give the cert(s) and key place"""
        
        #if the message is a big one we should digest it
        dg=DigestMan()
        dataSign=dg.gen_buf_hash(dataSign)
        
        ch=chainMan()
        
        #check basic things
        if not ch.load_chain(certplace, tip=0):
            return False
        
        #testing the chain
        if not ch.create_chain():
            return False
        
        #Gets the X509 objects as a stack
        stack=ch.dumpto_stack()
        
        del ch
        
        #create a buffer to store the data to be signed
        tosign=self.makebuf(dataSign)
        
        #return "Process cut"
        try :
            #Loading the private key
           
            self.sm.load_key(keyplace,certplace[0])
            #print stack
            #setting the stack we prepared
            
            #Not used for now 
            self.sm.set_x509_stack(stack)
            
            #The flags is detached because we dont want to store the original message in the pkcs7
            flagset=SMIME.PKCS7_DETACHED
            
            #print "The flagset is :",flagset
            
            self.__p7=self.sm.sign(tosign,flags=flagset)
            #print self.__p7
        
        except SMIME.SMIME_Error,e:
            print "Error with signing process",e
            return False
        
        except SMIME.PKCS7_Error,e:
            print "Pkcs7 File Error :",e
            return False
        
        except Exception,e:
            print "Any error",e
        
        #print  self.p7
        try :
            out=BIO.MemoryBuffer()
            self.__p7.write(out)
            
        except BIO.BIOError,e:
            print "Memory Error :",e
            return False 
        
        #Storing the signature into a file
        res=Cutil.file_operator(signature_place, 1, out.read())
        
        if not res or res==-1:
            print "Writing to file failed"
            return False
            
        
        print "The signature saved to :%s"%(signature_place)
        return True    
        #print self.p7.type()
        
    
    def verify_sign(self,data,signature_place):
        """ Verifies the signature against the data"""
        #create a BIO.Memory object
        dg=DigestMan()
        data=dg.gen_buf_hash(data)
        
        if not self.verify_signers(signature_place):
            return False
            #pass
        
        self.dataBuf=self.makebuf(data)
        
        if not data :
            print "Supply data to verify with"
            return False
        
        #print self.dataBuf.read()
        #Load the pkcs7 document
        try :
            
            #Make a stote and stack object just for argument list
            #we dont need them actually
            #xStore=self.create_store(["chain/cacert.pem"])
            xStore=X509.X509_Store()
            
            #stW=stackWork()
            #sk=stW.add_chain(["chain/cacert.pem"])
            sk = X509.X509_Stack()
            
        
            self.sm.set_x509_stack(sk)
            self.sm.set_x509_store(xStore)
            
            #Sets the flags to noverify which means that the verification of
            #the signers was made above
        
            flagset=SMIME.PKCS7_NOVERIFY
            
            #verify the signature it is a M2Crypto openssl method
            res=self.sm.verify(self.__p7,self.dataBuf,flags=flagset)
            #print res
            if not res:
                return False
            else:
                return True
            
        except SMIME.SMIME_Error,e:
            print "Error while setting pkcs7 verification process :",e
            return False
        except SMIME.PKCS7_Error,e:
            print "Pkcs Error",e
            return False
        
        
    

    def verify_signers(self,signature_place):
        """ The module will control the signers in the pkcs7 doc
        1)If they are valid
        2)If they are modified
        3)is a valid chain
        4)check with db if it is there
         If all Ok return true else false"""
        try:
            
            if not os.path.exists(signature_place):
                print "No signature file"
                return False
            
            tempSt=self.get_cert_from_sign(signature_place)
            if not tempSt:
                return False
            
            #Loading the document in p7 object for upper method
            self.__p7=SMIME.load_pkcs7(signature_place)
            #---The OLD Code-----
            #sk = X509.X509_Stack()
            
            #print "The p7 file loaded"
            #print self.__p7.get0_signers(sk)
            #del sk
            
        except SMIME.SMIME_Error,e:
            print "Error while setting pkcs7 verification process :",e
            return False
        except SMIME.PKCS7_Error,e:
            print "Pkcs Error",e
            return False
            
            
        res=tempSt.stack_control()
        #if res is present it is a hash list so check if it is in db
        if res:
            #print res
            db=DbCert()
            if db.dup_control(res[0]):
                
                #Showing the chains to user
                printResult=list_chain(res[1],tip=1)
                print "The chain is loaded in your browser (Firefox)"
                
                if not printResult:
                    return False
                
                answer=raw_input("The chain in signature is not in db what do you want to do? \n(c)ontinue,(s)top")
                
                #call the lister function with tip=1 parameter to know that you pass x509 objects
                #add option to show the cert in html format for now...
                
                if answer=="c":
                    return True
                #print "The chain is not in db what do you want todo?"
                return False
            else:
                print "The chain  is in db verification continues..."
                return True
            
    
        
        else:
            return False

    def show_signer(self):
        """ List info about the signer that is in pkcs7 document"""
        sk = X509.X509_Stack()
        
        tempSt=self.__p7.get0_signers(sk)
        
         
        ldb=ListDb(tempSt.pop(),tip=1)
        ldb.per_info()
        
    def create_store(self,fname=None):
        """ Returns a store object according to its content"""
        #get it only from a file
        stor=X509.X509_Store()
        
        if fname:
            if len(fname)==1:
                stor.load_info(fname[0])
                
            
            #if we entered a list of files
            else:
                for f in fname:
                    x=X509.load_cert(f)
                    stor.add_x509(x)
                    
        
        return stor
    

    def get_cert_from_sign(self,signature_place):
        """Takes all the certs from the signature if any and then
        places them into a stack object and returns to be controlled"""
        
        #command which extracts all the data from pkcs7 document
        command="openssl pkcs7 -in %s -print_certs"%(signature_place)
        #print command
        certs=os.popen3(command)
        
        if certs[2].read()!='':
            print "Openssl Error :",certs[2].read()
            return False
        
        
        patrn=re.compile(r'(-----BEGIN CERTIFICATE-----?.*?-----END CERTIFICATE-----?)',re.S)
        a=re.findall(patrn, certs[1].read().strip())
        
        stack=stackWork()
        
        if not stack.load_stack_buffer(a):
            print "Chain in the signature can not be loaded into stack object!"
            return False
        
        
        return stack
    
    def print_signers(self,signature_place):
        """ Shows the cert chain into browser for now"""
        if not os.path.exists(signature_place):
                print "No signature file"
                return False
            
        tempSt=self.get_cert_from_sign(signature_place)
        if not tempSt:
            return False
            
        res=tempSt.stack_control()
        #if res is present it is a hash list so check if it is in db
        if not res:
            return False
        
        printResult=list_chain(res[1],tip=1)
        
        if printResult:
            print "The chain is loaded in your browser (Firefox)"
            return True
        
        else:
            return False

if __name__=="__main__":
    
    pkc=pkcs7Work()
    #pkc.get_cert_from_sign("signature.sig")
    #print pkc.create_store(["chain/cert2.pem","chain/cert1.pem","chain/cacert.pem"])
    #pkc.create_store("chain.pem")
    #print pkc.make_sign("chain/key2.pem", ["chain/cert2.pem","chain/cert1.pem","chain/cacert.pem"], "Selmlar","signature.sig")
    #print pkc.verify_sign("Selmlar", "signature.sig")
    #print pkc.verify_signers("signature.sig")
    #pkc.show_signer()