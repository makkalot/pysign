#custom imports
from cUtil import Cutil
from cert import X509Man
from digest.Hasher import DigestMan


#3rd party
from M2Crypto import X509 

class chainMan(object):
    """ Loads, creates and controls the chains"""
    
    def __init__(self):
        self.__certs=[] #Will store the certs
        self.__cert_stack=[] #The lat chain
        
    
    def load_chain(self,chain_place,tip=0):
        """ Gets the certs from a list of files or from a list of buffers
        if tip=0 it is from file list,if tip=1 it is a cert Object list"""
        
        for file in chain_place:
            try:
                if tip==0:
                    xm=X509Man(X509.load_cert(file))
                elif tip==1:
                    xm=X509Man(file)
                    
            except Exception,e:
                print "Loading Error",e
                return False    #We should make some main verifications first checksum of the cert we load
                #print xm.check_ca()
            
            #if not xm.check_sum():
                #return False #it was modified
            
            
            #chect its dates
            if not xm.is_valid():
                "Using an old certificate???"
                return False
            
            self.__certs.append([str(xm.person_info("issuer")),str(xm.person_info("subject")),xm.get_cert()])
            del xm
            
        return True
            
        #print self.__certs
        
    def create_chain(self):
        """ From files that are uploaded by args creates a valid chain
        True if created,else False"""
        
        #starting point
        found=False

        
        #search if there is a root cert
        for i in self.__certs:
            
            if i[0]==i[1]:
                
                #print "The root Ca is :%s"%(i[0])
                self.__cert_stack.append(self.__certs.pop(self.__certs.index(i)))
                
                find=self.__cert_stack[0][0]
                found=True
                
                break
        
        if not found: # So we should choose a starting point
            issuer_list=[i[0] for i in self.__certs]
            #print issuer_list
            
            sub_list=[i[1] for i in self.__certs]
            #print sub_list
            
            for i in issuer_list:
                if not i in sub_list:
                    #print "The starting point is :%s"%(i)
                    found=True
                    find=i #The next issuer to search
                    
                    break # No need to stay anymore
                
        while found :
            
    
    #Before enter set it
            found=False
            
            for cert in self.__certs: 
                if find==cert[0]:
                    
                    find = cert[1]
                    found = True
                    #Remove from the list
                    self.__cert_stack.append(self.__certs.pop(self.__certs.index(cert)))
                    break #out of the loop
            
            if not self.__certs:
                found = False
        
        if self.__certs:
            print "The chain can not be constructed "
            #print "Remaining :%s"%(self.__certs)
            del self.__cert_stack
            return False
            
        else :
            #print "The cert chain is as follow:"
            #print self.__cert_stack
            return True
   
    
    def dumpto_stack(self):
        """ That one dumps all the stuff created with create_chain method"""
        newStack=X509.X509_Stack()
        
        
        for i in self.__cert_stack[:len(self.__cert_stack)-1]:
            #print i[1]
            newStack.push(i[2])
        
        """i=len(self.__cert_stack)-1
        
        while i>0:
            print newStack.push(self.__cert_stack[i][2])
            i=i-1"""
            
            
        return newStack    

    def get_final(self):
        """ Returns the latest constructed chain"""
        if self.__cert_stack:
            return self.__cert_stack
        else:
            return None
        
    def get_hash_list(self):
        """ That method is needed when we look for a specific cert if it is 
        in the db so we need their hash list"""
        hash_list=[]
        #from root to client
        for cert in self.__cert_stack:
            tempCert=X509Man(cert[2])
            hash_list.append(DigestMan.gen_buf_hash(tempCert.get_cert_text()))
            
            del tempCert
        
        
        return hash_list 
            
if __name__=="__main__":
    c=chainMan()
    c.load_chain(["chain/cacert.pem","chain/cert1.pem","chain/cert2.pem"])
    print c.create_chain()
    #print c.get_hash_list()
    #Test with the stack
    #print c.dumpto_stack().pop()
    #st=stackWork(c.dumpto_stack())
    #st.print_all()