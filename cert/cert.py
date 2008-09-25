#project Modules
from M2Crypto import X509 as x
from M2Crypto.BIO import MemoryBuffer

#Python Modules
from time import strftime,gmtime,strptime
import string



class X509Cert(object):
    """ Makes the X509 structure more useful for the purpose"""
    
    def __init__(self,thecert=None):
        
        if thecert:
            
            self.cert=thecert
        
        else:
            self.cert=x.X509()
            
    
        #print self.cert
    def set_from_buf(self,certData,format=0):
        """ The method sets the cert with data from a buffer
        format 0 is for pem and 1 for der"""
        self.cert=x.load_cert_string(certData)
        return True
         #to check if it was loaded
        
    def set_cert(self,certObj):
        """ Sets the global cert object from outside the class"""
        self.cert=certObj
        
    def cert_hash(self):
        """
        It is all of the certs hash
        """
        import string
        return string.lower(str(self.cert.get_fingerprint("sha1")))

    def list_info(self,tam=None):
        """ Lists some info about the cert"""
        if tam:
            print self.cert.as_text()
        else:
            #print "Cert version :%s"%(self.cert.get_version())
            print "Beginnig Date :%s"%(self.cert.get_not_before())
            print "End Date :%s"%(self.cert.get_not_after())
            #print "The public key is :%s"%(self.gPubkey())
            print "*****************************************************"
            print "The issuer info :"
            self.cert_detail(self.cert.get_issuer())
            print "*****************************************************"
            
            print "Certs owner info :"
            self.cert_detail(self.cert.get_subject())
            #print "Is it a Ca cert :%s"%(self.cert.check_ca())
            print "******************************************************"
            print "The fingerprint is :%s"%(self.cert.get_fingerprint("sha1"))
        
        #print self.cert.as_pem()
        #print self.cert.as_der()
        
    def store_tofile(self,fname):
        """ Loads the certficate to a file"""
        self.cert.save(fname)
        print "Certificate saved to :",fname
        

    def get_public_key(self):
        """ Return Back the certs public key"""
        self.pkey=self.cert.get_pubkey()
        return self.pkey
    
    def cert_detail(self,detailObj):
        """ It is passed a XNAME object"""
        self.xDetail=detailObj
        self.printFormat=self.optionClear()
        
        for key in self.xDetail.nid.keys():
            res=self.xDetail.get_entries_by_nid(self.xDetail.nid[key])
            #print res
            
            if res:
                #print key
                #print res[0].get_data()
                print "%s : %s"%(self.printFormat[key],res[0].get_data())
                
    def optionClear(self):
        """ Makes some options clearer in the certificate"""
        
        opClr={'C'                      : 'Country Name', 
         'SP'                     : 'State or Province', 
         'ST'                     : 'Province or State', 
         'stateOrProvinceName'    : 'State Province', 
         'L'                      : 'Locality Name', 
         'localityName'           : 'Local Name', 
         'O'                      : 'Organization', 
         'organizationName'       : 'Organization Name', 
         'OU'                     : 'Org Unit Name', 
         'organizationUnitName'   : 'Organization Unit Name', 
         'CN'                     : 'The Common Name', 
         'commonName'             : 'Common Name', 
         'Email'                  : 'Email', 
         'emailAddress'           : 'email', 
         'serialNumber'           : 'Serial Number', 
         'SN'                     : 'Surname', 
         'surname'                : 'The Surname', 
         'GN'                     : 'Given Name', 
         'givenName'              : 'GivenName' 
              }
        return opClr


    def is_valid(self):
        """ Checks if the certificate is still valid and is not expired..."""
        self.expDate=str(self.cert.get_not_after())
        
        #Get rid off GMT thing
        self.expDate=string.replace(self.expDate, "GMT", "").strip()
        self.expDate=string.replace(self.expDate, "UTC", "").strip()
        #print self.expDate
        
        #Convert to a valid type for easy comparison
        self.expDate=strptime(self.expDate,"%b %d %H:%M:%S %Y")
        #print self.expDate
        
        #Get the current time in same format
        curTime=strptime(strftime("%b %d %H:%M:%S %Y"),"%b %d %H:%M:%S %Y")
        #print type(curTime)
        
        if self.expDate>curTime:
            #print "It is still valid"
            return True
        else:
            #print "It expired"
            return False
        
        
    def person_info(self,tip="subject"):
        """ Gets the sides info ex signer(issuer),subject etc."""
        xn=None
        
        if tip=="subject":
            xn=self.cert.get_subject()
            
        elif tip=="issuer":
            xn=self.cert.get_issuer()
        else:
            return None
    
        return str(xn).strip() #XName Object
    
    
    def get_detail(self,tip="issuer"):
        """ Returns a tuple to be displayed"""
        xn=self.person_info(tip)
        
        clear_dic={
                   'C':'country',
                   'CN':'commoName',
                   'emailAddress':'eadress',
                   'SP':'statePro',
                   'OU':'department',
                   'O':'company'
                   }
        
        toPrint={}
        
        #print type(xn)
        #Take the country firstly
        
        for k in clear_dic.keys():
            entry=xn.get_entries_by_nid(xn.nid[k])
            toPrint[clear_dic[k]]=str(entry[0].get_data())
        
        
        return toPrint
    
    def get_cert(self):
        """ Getting the certificate back it is an object"""
        return self.cert
  
    def get_date_info(self):
        "returns start date,end date and if it is valid"
        
        date_info={}
        
        date_info['sdate']=str(self.cert.get_not_before())
        date_info['edate']=str(self.cert.get_not_after())
        
        if self.is_valid():
            date_info['v']="Valid"
        else:
            date_info['v']="Expired"
            
        return date_info
        
    
        
    def get_cert_text(self,format=0):
        """Format 0 is pem,format 1 is der 
        Extracts the encrypted base64 text from certificate"""
        #print self.cert.verify()
        #print self.cert.check_ca()
        #get it according to its format
        if format==0:
            return self.cert.as_pem()
        elif format==1:
            return self.cert.as_der()

    def is_ca(self):
        """
        A simple wrapper method for check_ca because 
        it returns some error codes which are not very
        Pythonic .. if it is return True else False
        """

        if self.cert.check_ca() == 0:
            return False
        else:
            return True

        
    
    def verify_issuer(self,issuer_public_key):
        """
        That method checks if its signature when
        is decrypted by public key of the issuer
        will give us the fingerprint of that cert
        A very useful method to check if some other cert
        is the issuer of that ! (in chain validation)
        """
        result =  self.cert.verify(issuer_public_key)
        #ah it is C style :)
        if result == 0:
            return False
        else:
            return True

    def __cmp__(self,other_cert):
        """
        Compare if two certs are the same
        """
        #first check if the subject fields are same
        #second check if the issuer info is same
        #third check the fingerprints --it is the exact match --
        if not str(self.person_info("issuer")) == str(other_cert.person_info("issuer")):
            print "Mismatch in issuer fields between 2 certs"
            return -1
        
        if not str(self.person_info("subject")) == str(other_cert.person_info("subject")):
            print "Mismatch in subject fields between 2 certs"
            return -1

        if not self.cert_hash() == other_cert.cert_hash():
            print "The hashes of 2 certs are not same"
            return -1

        #if you pass all you pass the exam :)
        return 0



if __name__=="__main__":
    cert=x.load_cert("/home/makkalot/my-svns/old_imza/imzaci/chain/cert2.pem")
    s=X509Cert(cert)
    
    #load its parent to see if it is ok ?
    cert2=x.load_cert("/home/makkalot/my-svns/old_imza/imzaci/chain/cacert.pem")
    cert_parent = X509Cert(cert2)
    print "Verify that ??"
    print s.verify_issuer(cert_parent.get_public_key())
    print s == cert_parent

    print "Control to see if it is a CA"
    print s.cert.check_ca()
    print cert_parent.cert.check_ca()
    #s=X509Man()
    
    #s.list_info()
   
    #print s.gPubkey()
    #s.store_tofile("bisi.pem")
    #print s.is_valid()
    #print s.get_cert_text()
    #print s.check_sum()
    #print s.person_info()
    #s.get_detail("issuer")
    #print s.get_date_info()
    #print s.cert.get_subject() 
    #print s.cert.get_issuer()
    
