#project Modules
from M2Crypto import X509 as x
from M2Crypto.BIO import MemoryBuffer

#Python Modules
from time import strftime,gmtime,strptime
import string



class X509Man(object):
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
        
        #buf=MemoryBuffer()
        #buf.write(certData)
        
        #Loads  into global object
        #print certData
        self.cert=x.load_cert_string(certData)
        #print self.cert.get_not_before()
        
        return True
         #to check if it was loaded
        
    def set_cert(self,certObj):
        """ Sets the global cert object from outside the class"""
        self.cert=certObj
        
        
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
        

    def gPubkey(self):
        """ Return Back the certs public key"""
        #print self.cert.get_pubkey()
        self.pkey=self.cert.get_pubkey()
        self.buffer=MemoryBuffer()
        
        #print self.pkey
        self.pkey.save_key_bio(self.buffer, cipher=None)
        self.pub=self.buffer.read()
        
        #Because the default is PRIVATE even if it is public
        self.pub=string.replace(self.pub, "PRIVATE", "PUBLIC")
        
        return self.pub
    
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
    
        return xn #XName Object
    
    
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
        
    
    def check_sum(self):
        """ Checks if the cert has been modified for any reasons"""
        if self.cert.verify()==0:
            #print "Hash is valid"
            return True
        else:
            print "The cert has been modified"
            return False 
        

if __name__=="__main__":
    #cert=x.load_cert("chain/cert1.pem")
    #s=X509Man(cert)
    s=X509Man()
    
    #s.list_info()
    #print s.gPubkey()
    #s.store_tofile("bisi.pem")
    #s.is_valid()
    #print s.get_cert_text()
    #print s.check_sum()
    #print s.person_info()
    #s.get_detail("issuer")
    #print s.get_date_info()
    
    