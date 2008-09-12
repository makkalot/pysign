from OpenSSL import crypto
import string

class Cutil(object):
    """ Class which is filled with static methods for 
    just daily usage..."""
    
    def __init__(self):
        """ Constructor does nothing"""
        pass
    
    def nice_digest(dgst):
        """ To show the digest nicely..."""
        ng=string.replace(dgst, ":", "")
        return string.lower(ng)
    
    nice_digest=staticmethod(nice_digest)
    
    def file_operator(f_place,op,data=None):
        """ It is used many times so it is needed for io Operations"""
        try :
            
            if op==0:
                tip="r"
                file=open(f_place,tip)
                
                toRet=file.read()
                file.close()
                return toRet
            
            elif op==1:
                tip="w"
                file=open(f_place,tip)
                
                if data:
                    file.write(data)
                    file.close()
                    return True
                else:
                    return False
        
        except IOError:
            print "IOErrror occred in utility"
            return -1
        
    file_operator=staticmethod(file_operator)