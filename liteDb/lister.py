from sign.cert import X509Man
from htmlTemplate import certInfo 
#temp
from initializer import DbCert
#system import
import os
#3rd party
from M2Crypto import X509 as x

class ListDb(X509Man):
    """ that class wll generate some info about the certs and chains in a readable format"""
    
    def __init__(self,buffer=None,tip=0):
        """ initialize thing to show can be a buffer or a file...
        for tip 0:is memeory,1:is for normal cert,2:is for a file"""
        #the html that will be stored
        self.certText=""
        
        
        if buffer:
            if tip==0:
                super(ListDb,self).__init__()
                super(ListDb,self).set_from_buf(buffer)
            elif tip==1:
                super(ListDb,self).__init__(buffer)
                
        else:
            print "Nothing Loaded"
             
            #print super(ListDb,self).check_sum()
            #print super(ListDb,self).get_detail()
            
        
        
        
    def per_info(self,name=None):
        """ Generates the part that is concerned with issuer and subject nad stores into
        a html file for now..."""
        
        issuer=super(ListDb,self).get_detail("issuer")
        subject=super(ListDb,self).get_detail("subject")
        dater=super(ListDb,self).get_date_info()
        
        self.cert="".join([certInfo['beginTag']%("Certificate Information"),certInfo['personData']%("Issuer Info",issuer['country'],issuer['commoName'],\
                        issuer['eadress'],issuer['statePro'],issuer['department'],issuer['company']),certInfo['personData']\
                        %("Subject Info",subject['country'],subject['commoName'],\
                        subject['eadress'],subject['statePro'],subject['department'],subject['company']),\
                        certInfo['dateInfo']%(dater['v'],dater['sdate'],dater['edate']),certInfo['endTag']])
        
        if not name:
            tofile=open("test.html","w")
        else:
            tofile=open(name,"w")
            
        tofile.write(self.cert)
        tofile.close()
        
        #os.system("/usr/bin/firefox test.html")
        
def list_chain(name,tip=0):
    """ Will list the chain info in a html page 
    About tip : if tip==0 name is a chain_name in the database
    if tip==1 the name is a list of X509 objects
    it was made to avoid writing the same method again..."""
    
    if tip==0:#it it will be retrieved from database
        dc=DbCert()
        res=dc.get_certids(name)
    
    #it will be retrieved from a cert list
    else:
        res=name
    #The res is a list of certification ids in the db    
    if not res:
        return False
        
    final=[]
    final.append(certInfo['beginTag']%("Chain Information"))
    bindent="<blockquote>"
    eindent="</blockquote>"
        
    count=0
    for c in res:
         
        final.append(3*bindent)
            
        linkname="".join(["cert",str(count)])
        link="".join([linkname,".html"])
        
        #print certInfo['chainInfo']%(link,linkname)    
        final.append(certInfo['chainInfo']%(link,linkname))
        count=count+1
        
        #Store also the cert in another link:
        if tip==0:
            #pass it as an string 
            ls=ListDb(buffer=dc.get_certData(c[0]))
            #print dc.get_certData(c[0])
        else:
            #pass it as an object
            ls=ListDb(c,tip=1)
            
        ls.per_info(link)
            
    final.append(eindent*count*3)
    final.append(certInfo['endTag'])
            
        
        
    tofile=open("chain.html","w")    
    tofile.write("".join(final))
    tofile.close()
        
    os.system("/usr/bin/firefox chain.html")
    
    return True
        
        
if __name__=="__main__":
    #dc=DbCert()
    list_chain("bigchain")
    
    #l=ListDb(buffer=dc.get_certData(21))
    #l.per_info()
    #l=ListDb()
    #l.list_chain("bigchain")