#from pysqlite2 import dbapi2 as sqlite
import sqlite
import base64
import os

#custom imports
from dbMain import LiteDb
from queryList import dbConstants
from digest.Hasher import DigestMan
from sign.chainManage import chainMan
from sign.cert import X509Man

class DbCert(LiteDb):
    """Will import,initialize,delete,list features from db that
    certs and chains are stored"""
    
    def __init__(self):
        """ Triggers the parent one to be initialized"""
        #print sqlInitCom['dbname']
        super(DbCert,self).__init__(dbConstants.DBNAME)
        #print dbConstants.DBNAME
        cert=X509Man()
        
    
    def c_tables(self):
        """ Creates tables and triggers needed for certificate management"""
        if os.path.exists(dbConstants.DBNAME):
            print "Db exists it's been deleted"
            os.remove(dbConstants.DBNAME)
            super(DbCert,self).renew_conn()
        
        query=list(dbConstants.sqlInitCom.keys())
        query.sort()
        
        #print query
        
        
        for q in query:
            #print q
            res=super(DbCert,self).updateS(dbConstants.sqlInitCom[q])
            #print dbConstants.sqlInitCom[q]
            if res==-1:
                return False
        
        print "Initialization done..."
        
        return True
    
    def import_cert(self,parent_chain,cert_list):
        """ That one will import the cert into the db"""
        #q="insert into certs values (null,1,\'naberlan blob\','12345')"
        #q="update certs set ch_id=12 where ce_id=1"
        
        for c in cert_list:
            tempCert=X509Man(c[2])
            q="insert into certs values (null,%s,'\%s\',\'%s\')"%(parent_chain[0],tempCert.get_cert_text(),c[0])
            #print q
            res=super(DbCert,self).updateS(q)
            del tempCert
        
            if res==-1:
            
                print "Cert insertion Failed"
                return False
            #print "Cert inserted"
        
        return True#success 
            
    def import_chain(self,file_list,name=None):
        """ Inserts a new entry to db in chain table also calls the
        import_cert to complete the job
        1.take cert stack
        2.compute their hash
        3.if chain exists it fails
        4.if root exists warning
        5.If not there it is inserted as trusted cause we import it (May be changed later)"""
        
        """ Verification Process"""
        ch=chainMan()
        if not ch.load_chain(file_list):
            print "Cert verification failed"
            return False
        
        #Test the chain if it is valid
        if not ch.create_chain():
            print "The chain is not valid"
            return False
        
        #get the final one
        chain_st=ch.get_final()
        del ch
        
        #use the slot 0 of the list that we recieved
        
        #get the hashes
        
        for c in chain_st:
            #print c[2]
            tempCert=X509Man(c[2])
            c[0]=DigestMan.gen_buf_hash(tempCert.get_cert_text())
            del tempCert
            #print c[0]
         
        #check first if the same chain is in the db
        if not self.dup_control([c[0] for c in chain_st]):
            #print "The chain exists in the db"
            return False
        
        #return "Process cut :)"
        
        
        q2="select max(c_id) from chains"
        
        res=super(DbCert,self).selectS(q2,"one")
        
        
        if res==-1:
            
            #print res
            print "Chain insertin process failed"
            return False
        
        if not name:
            if res[0]:
                print res[0]
                q="insert into chains values (null,\'%s\',\'trusted\')"%("".join(["name",str(res[0])]))
            else:
                q="insert into chains values (null,\'%s\',\'trusted\')"%("name1")
            
        else:
            q3="select * from chains where name=\'%s\'"%(name)
            res=super(DbCert,self).selectS(q3,"one")
            
            if res:
                print "Name exists"
                return False
            
            q="insert into chains values (null,\'%s\',\'trusted\')"%(name)
            
            
            
        
        res=super(DbCert,self).updateS(q)
        
        
        if res==-1:
            print "Chain insertion error"
            return False
        #print "New chain inserted"
        
        #super(DbCert,self).renew_conn()
        
        res=super(DbCert,self).selectS(q2)
        
        
        if not res or res==-1:
            #print res
            #print "Chain insertin process failed"
            return False
        
        #print "parent chain number taken"
        
        
        if not self.import_cert(res[0], chain_st):
            return False
        
        print "Import process succesfull"
        return True
        
        
        
    def delete_chain(self,name):
        """ Deletes a chain from th db so all certs are gone in that case"""
        q="delete from chains where name=\'%s\'"%(name)
        q2="select * from chains where name=\'%s\'"%(name)
        
        res=super(DbCert,self).selectS(q2)
        
        if not res or res==-1:
            #print res
            print "Chain doesnt exists"
            return False
        
        res=super(DbCert,self).updateS(q)
        print res
        if res!=-1:
            #print "Succes"
            return True
        else :
            
            #print "Failed"
            return False
 
    
    def dup_control(self,hash_list):
        """ Checks if the current chain is already in the db.If there is a duplication return False
        else return True if the chain is not there"""
        
        q1="select c_id from chains order by c_id"
        res=super(DbCert,self).selectS(q1)
        #print res
        #print hash_list
        #If there is no chains
        if not res:
            return True
        
        for ch_id in res:
            #print ch_id
            #The res is a tuple in a list if present
            res=super(DbCert,self).selectS("select cert_sum from certs where ch_id=%s order by ce_id"%(ch_id[0]))
            
            #The control is from the root to end
            #the root control... if you want may activate that one later
            #if res[0][0]==hash_list[0]:
                #print "Root exists"
                #here we may have a raw_input to ask to user if we want to continue
                #return False
            
            #if root not equal and num of items it has are not same so it is not in db
            if len(res)!=len(hash_list):# so goto the beginnig of the loop
                #print "Length failure"
                continue
            
            
            dbCerts=[cert[0] for cert in res]
            #debug statements
            #print "Database Certs are :"
            #print dbCerts
            
            #print "The others are :"
            #print hash_list
            
            if dbCerts==hash_list:
                print "Chain is already in the database"
                return False
                    
                
        return True
        
        
    
    def get_certData(self,cert_id):
        """ Pulls a cert from db to show its content ..."""
        
        q="select cert_data from certs where ce_id=%s"%(cert_id)
        
        res=super(DbCert,self).selectS(q,"one")
        #print res.encode()
        
        if not res:
            return False
        
        
        return str(res[0][1:])#because the db inserts a / char at the beginnig of the cert string 
        #return  base64.encodestring(res[0])
        
    def change_trust(self,name,deg=0):
        """ That method changes the trust degree for the given chain
        @args name : is the chains name or 
        deg: is the trust degree 0:not trusted,1:trusted,2:not sure"""
        
        degs={0:"not trusted",
              1:"trusted",
              2:"not sure"}
        
        
        if not deg in degs.keys():
            print "Invalid trust degree"
            return False
        
        q2="select * from chains where name=\'%s\'"%(name)
        
        res=super(DbCert,self).selectS(q2)
        
        if not res or res==-1:
            #print res
            print "Chain doesnt exists"
            return False
        
        
        
        q="update chains set trust_deg=\'%s\' where name=\'%s\'"%(degs[deg],name) 
        #print q
        res=super(DbCert,self).updateS(q)
        
        if res!=-1:
            return True
        else :
            return False
        
    def get_certids(self,name):
        """ Simple method that just gets certs ids for a given chain name..."""
        q="select ce_id from certs,chains where ch_id=c_id and name=\'%s\' order by ce_id"%(name)
        res=super(DbCert,self).selectS(q)
        
        if not res:
            return False
        
        else :
            return res
        
    def list_chains(self):
        """ Simple method just pulls all the chains from db"""
        q="select * from chains"
        
        res=super(DbCert,self).selectS(q)
        
        if not res:
            return False
        
        else :
            final=[]
            for ch in res:
                final.append("".join(["Chain Name : ",ch[1]," Trust Degree : ",ch[2],"\n"]))
                final.append("".join(["**************************************************\n"]))
            return "".join(final)
            
        
        
        
        

if __name__=="__main__":
    dc=DbCert()
    #print dc.c_tables()
    #dc.import_cert()
    #print dc.import_chain(["chain/cacert.pem","chain/cert1.pem","chain/cert2.pem"],"bigchain")
    #print dc.import_chain(["sert/newcert.pem"],"mycert")
    #dc.delete_chain(1)
    #"chain/cacert.pem",
    #print dc.get_certData(2)
    #print dc.change_trust("name1", 2)
    #print dc.delete_chain("bigchain")
    #print dc.get_certids("bigchaine")