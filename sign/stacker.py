from M2Crypto import X509

from cert import X509Man
from chainManage import chainMan


class stackWork(object):
    """ That class will handle the certification chains"""
    
    def __init__(self,nStack=None):
        """ Make a stack object"""
        if nStack:
            self.st=nStack
        else:
            self.st=X509.X509_Stack()
        
    #No usage for NOWW!
    def add_chain(self,file_list):
        """ Takes the file list of the files that should 
        construct the chain. It is better list to be in sequence from ca to client"""
        
        for x in file_list:
            cert=X509.load_cert(x)
            self.st.push(cert)
            
        print "The chain was loaded"
        
        return self.st
            

    def print_all(self):
        """ Gets all the cert to be shown (just for test purpose)"""
        xs=self.st.pop()
        
        
        while xs:
            
            print "######################################################"
            xShow=X509Man(xs)
            xShow.list_info()
            del xShow
            xs=self.st.pop()
            print "######################################################"
            
        #print "End of the show"
    def stack_control(self):
        """ Controls if the stack is Ok and valid and etc..."""
        #initial loop point
        xs=self.st.pop()
        #instance to control and manage chains
        ch=chainMan()
        
        cert_list=[]
        while xs:
            #print xs
            cert_list.append(xs)
            xs=self.st.pop()
         
        #Loading with cert object option   
        if not ch.load_chain(cert_list,1):
            print "Cert verification failed while verifyin basic things"
            return False
        
        if not ch.create_chain():
            return False
        
        #stack control succesfull gets the hash of the list to compare them
        #with those in the db
        #the second one is (chained cert objects)
        return (ch.get_hash_list(),[a[2] for a in ch.get_final()])
    
    
    def load_stack_buffer(self,bufCerts):
        """ The method loads the certs into a stack object but from a buffer not file
        system. It is useful when got the certs from signature file..."""
        if not bufCerts:
            return False
        
        for cert in bufCerts:
            x=X509Man()
            #creates the object from buffer
            x.set_from_buf(cert)
            self.st.push(x.get_cert())
            del x
         
        #remove the comment if any problem occurs    
        #self.print_all()
           
        return True
        
        
            
            
            
        
if __name__=="__main__":
    stack=stackWork()
    stack.add_chain(["chain/cert1.pem","chain/cert2.pem"])
    #stack.print_all()
    stack.stack_control()