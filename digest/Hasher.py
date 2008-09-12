from Crypto.Hash import MD5,SHA
from cryptUtility import Cutil
from fileList import StructMe

import os

class DigestMan(object):
    """ The class generates sha1 or md5 hashes of the files"""
    
    def __init__(self):
        """ Some initialization stuff"""
        pass
    
    def generate_hash(fname,tip):
        """ Returns the hash of the files even big ones"""
        if tip=="sha1":
            h=SHA.new()
        if tip=="md5":    
            h=MD5.new()
            
        try :
            file=open(fname,"r")
            data=file.read(65536)
            
            while data:
                h.update(data)
                data=file.read(65536)
            
            
            file.close()
               
        
            h.digest()
            finald=h.hexdigest()
        
            del h #clear unused
            return Cutil.nice_digest(finald)
        
        
        
        except IOError:
            print "IOError occured :"
            return 1
    
    generate_hash=staticmethod(generate_hash)

    def gen_buf_hash(data):
        """ Generates the sha1 hash of a mem buffer"""

        h=SHA.new()
        h.update(data)
        h.digest()
        
        finald=h.hexdigest()
        
        del h #clear unused
        return Cutil.nice_digest(finald)
    
    gen_buf_hash=staticmethod(gen_buf_hash)    
    
    def store_hash(self,root_dir):
        """ Calls the file lister and computes all the hashes of the files"""
        
        fl=StructMe(root_dir)
        files=fl.FileStructure()
        
        if root_dir.endswith('/'):
            root_dir=root_dir[:-1]
        #print files
        
        try :
            hash_file=open("".join([root_dir,".txt"]),"w")
            buffer=[]
            
            
            for f in files :
                
                buffer.append("".join([f,"\n"]))
                chash=DigestMan.generate_hash(f, "sha1")
                buffer.append("".join([chash,"\n"]))
                #hash_file.write("".join(["(",f,") = ",chash]))
            
            hash_file.writelines(buffer)    
                
            hash_file.close()
            print "All hashes written to file :","".join([root_dir,".txt"])
            #print os.getcwd()
            return True
                
        except IOError ,i:
            print "IO Failed :",i
            return -1    
            
        
            
        
if __name__=="__main__":
    d=DigestMan()
    #print d.generate_hash("/home/makkalot/Harun.Yahya.The.Secret.Of.The.Test.Bulgarian.mpg", "sha1")
    #print d.store_hash("svn")
    #print d.gen_buf_hash("Merhabalar")