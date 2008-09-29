#custom imports
from imzaci.cert.cert import X509Cert
#3rd party
from M2Crypto import X509 

class X509ChainManager(object):
    """ Loads, creates and controls the chains"""
    #some constants
    FILE_PLACE = 0
    M2CRYPTO_CERT=1
    X509_CERT = 2

    def __init__(self):
        #initialze all the stuff
        self.__clear_structures() 

    def load_chain(self,chain_place,tip=0):
        """ Gets the certs from a list of files or from a list of buffers
        if tip=0 it is from file list,if tip=1 it is a cert Object(M2crypto TYPE),if tip==2 then
        it is a X509Cert object (also very useful in our case for direct loading) list
        When loading we make a few controls which should be mentioned here:
        1)Check if the certs are valid(if they didnt expired ..)
        2)If some of them are CA have rights to sign put them to __ca_cert_stack
        3)If they dont have CA they are put ito the self.__subject_cert (it should be 1)
        4) If some of that conditions is broken then exit with False !
        """
        if not chain_place:
            return False

        if self.__should_initialize():
            self.__clear_structures()

        for chain_candidate in chain_place:
            try:
                if tip==self.FILE_PLACE:
                    cert_obj=X509Cert(X509.load_cert(chain_candidate))
                elif tip==self.M2CRYPTO_CERT:
                    cert_obj=X509Cert(chain_candidate)
                elif tip==self.X509_CERT:
                    cert_obj=chain_candidate
                    
            except Exception,e:
                print "Some error occured when trying to load the cert chain ",e
                return False    #We should make some main verifications first checksum of the cert we load
            
            #chect its dates
            if not cert_obj.is_valid():
                raise ChainValidationException("The cert in the chain with that subject: %s is expired "%(cert_obj.person_info()))
                return False

            if cert_obj.is_ca():
                self.__ca_cert_stack.append(cert_obj)
            else:
                self.__subject_cert.append(cert_obj)
            
            
        return True
            
        #print self.__certs


        
    def create_chain(self):
        """ From files that are uploaded by args creates a valid chain
        True if created,else False
        There are a few things we try here when constructing a chain
        1) Check if there is nothhing into the self.__ca_cert_stack if empty False
        2) Check if there is more into the self.__subject_cert if False
        3) Then if there is sth into self.__subject_cert search into the
        self.__cert_stack and find its signer if any continue if no False
        4) If there is no self.__subject_cert find a starting point and try
        to construct the cert
        Simple is good :)
        """
        #print "The current CA list is like :"
        #for ca in self.__ca_cert_stack:
        #    ca.list_info()
        #print "The subject list is like :"
        #for subj in self.__subject_cert:
        #    subj.list_info()

        if self.__final_chain:
            self.__final_chain = []

        if len(self.__ca_cert_stack) == 0:
            raise ChainValidationException("There is no CA certs into the chain you try to build.")
            return False

        if len(self.__subject_cert) > 1:
            raise ChainValidationException("There should be only one non CA cert into the chain")
            return False

        if len(self.__ca_cert_stack) == 1 and len(self.__subject_cert)==0:
            raise ChainValidationException("Only one cert was found we can not  construct the chain with one cert")
            return False

        if len(self.__subject_cert)>0:
            result = self.__construct_chain(self.__subject_cert[0])
            if not result :
                return False
            else:
                self.__chain_valid = True
                return True
            #continue while there is cert object to check
                          
        else:#if all of our certs are CA which is notvery wise but ...
            cert_index = self.__find_starting_index()
            if cert_index == -1:
                raise ChainValidationException("Chain can not be constructed no starting point found")
                return False
            current_cert = self.__ca_cert_stack[cert_index]
            result=self.__construct_chain(current_cert)
            
            if not result :
                return False
            else:
                self.__chain_valid = True
                return True

    def __construct_chain(self,current_cert):
        """
        Tries to construct the chain with starting point at
        current_cert so :
        1) We search for the issuer of the current_cert if find it
        2) When find the isuuer check check if it signed the cert here
        3) If all goes good we will have a fresh good chain :)
        """
        find_issuer = current_cert.person_info("issuer")
        #sometimes the passed cert is also a CA so
        #that breakes the normal behaviour if it is
        #a CA we should add it immediately to the list...
        if current_cert.is_ca():
            self.__final_chain.append(current_cert)

        while not current_cert is None:
            #did we found a match ?
            found = False
            for cert_check in self.__ca_cert_stack:
                #check if subject info equeals to issuer info
                #print "What we try is :"
                #print "The issuer to find :",find_issuer
                #print "The subject we check :",cert_check.person_info("subject")
                if cert_check.person_info("subject") == find_issuer:

                    #check if that CA has signed our current cert
                    if current_cert.verify_issuer(cert_check.get_public_key()):
                        self.__final_chain.append(cert_check)
                        current_cert = cert_check
                        find_issuer = current_cert.person_info("issuer")
                        found = True
                        break
                    else:
                        raise ChainValidationException("The cert with subject %s didnt sign the cert with subject %s the chain can not be constructed"%(cert_check.person_info("subject"),find_issuer))
                        return False
            
            if found == False and len(self.__ca_cert_stack) != len(self.__final_chain):
                raise ChainValidationException("There is no signer for cert with subject %s "%(current_cert.person_info("subject")))
                return False
                
            elif len(self.__ca_cert_stack) == len(self.__final_chain):
                #The chain is ok should exit from main while loop
                current_cert = None
                return True


    def __find_starting_index(self):
        """
        That method should not be called directly 
        The purpose is to find a certificate which is not a signer
        so the way to do that is find a subject that doesnt match to
        the issuer part of any of the self.__ca_cert_stack ... if find
        any just return the index otherwise return -1 for Failure
        """

        #first pickup a subject 
        for index,subject_pick_cert in enumerate(self.__ca_cert_stack):
            subj = subject_pick_cert.person_info("subject")
            found = False
            for sub_search_cert in self.__ca_cert_stack:

                if sub_search_cert.person_info("issuer") == subj:
                    #print "Index is ",index
                    found = True
                    break
            #yep that is our starting point
            if found == False :
                return index 

        return -1
    
    def dumpto_stack(self):
        """ That one dumps all the stuff created with create_chain method"""
        if not self.__chain_valid:
            raise ChainValidationException("It seems that chain is not constructed try running create_chain method first")
            return None
        
        newStack=X509.X509_Stack()
        for cert in self.__final_chain:
            #print i[1]
            newStack.push(cert)
            
        return newStack    

    def get_final(self):
        """ Returns the latest constructed chain"""
        if self.__chain_valid:

            return self.__final_chain
        else:
            raise ChainValidationException("It seems that chain is not constructed try running create_chain method first")
            return None

    def get_final_subject(self):
        """
        After you construct the chain get the subject
        """
        if self.__chain_valid:
            return self.__subject_cert[0]
        else:
            raise ChainValidationException("It seems that chain is not constructed try running create_chain method first")
            return None



    def is_chain_valid(self):
        return self.__chain_valid

    def __cmp__(self,other):
        """
        Override that because we need to compare chains 
        in db operations ...
        """
        if not self.__chain_valid or not other.is_chain_valid():
            print "It seems that chain is not constructed try running create_chain method first"
            return -1

        if len(self.__final_chain) != len(other.get_final()):
            return -1

        other_certs = other.get_final()
        for index,cert_compare in enumerate(self.__final_chain):
            if cert_compare != other_certs[index]:
                return -1

        return 0
    
    def __str__(self):
        result = ""
        for cert in self.__final_chain:
            result = "".join([result,"\n*************\n",str(cert)])
        return result


    def __iter__(self):
        """
        Simple iterator over final CA chain
        """
        return iter(self.__final_chain)

    def __clear_structures(self):
        """
        Cleares the data structures for maybe reusing the object for different
        objects and places ...
        """
        self.__final_chain=[] #Will store the final CA stack
        self.__ca_cert_stack=[] #The latest chain with CA's in it #the root is the latest one
        self.__subject_cert = [] #that will be the latest one in the chain which is
        #not a CA
    
        #sometimes we may need to know if the loaded certs are
        #controlled before ...
        self.__chain_valid = False

    def __should_initialize(self):
        """
        It tells if we need to initialize the structures useful 
        for reusing the X509ChainManager objects ...
        """
        if self.__final_chain or self.__ca_cert_stack or self.__subject_cert or self.__chain_valid:
            return True
        else:
            return False



def chain_manager_factory(chain_place,load_type):
    """
    A common factory function that returns back a
    X509ChainManager object
    """
    if not chain_place:
        print "No chain to load sorry "
        return None

    try:
        cm = X509ChainManager() #create an instance
        load_result = cm.load_chain(chain_place,load_type)
        if not load_result:
            print "Some error when loading the chain"
            return None

        create_result = cm.create_chain()
        if not create_result:
            print "The chain can not be constructed sorry "
            return None
        return cm
    except ChainValidationException,c:
        print c
        return None


class ChainValidationException(Exception):
    """
    Raised when we have some chain validation/creation error
    """
    
    def __init__(self, value=None):
        Exception.__init__(self)
        self.value = value
    def __str__(self):
        return "%s" %(self.value,)


if __name__=="__main__":
    pass

