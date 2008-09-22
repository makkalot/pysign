import glob
#custom loads
from imzaci.cert.cert import X509Cert
from imzaci.util.ssl_util import open_internal_db
from imzaci.cert.chain_manager import chain_manager_factory,X509ChainManager
"""
A module that supplies some cert util methods for getting and setting em
"""

def load_chain_dir(chain_dir):
    """
    Loads a chain of certs from a dir
    Only gets the .pem files from it
    """
    chain_place=load_cert_from_dir(chain_dir,get_all=True)
    result=chain_manager_factory(chain_place,X509ChainManager.X509_CERT)
    return result

def load_chain_file(chain_file):
    """
    Loads a chain from a single file
    Works for pattern :
    ----BEGIN CERT----
    ----END CERT-----
    """
    from imzaci.util.cert_util import parse_pem_cert
    import os

    if not os.path.exists(chain_file):
        print "Chain file doesnt exists"
        return None

    chain_place = parse_pem_cert(chain_file)
    if not chain_place:
        print "Error when loading the chain file ",chain_file
        return None

    result=chain_manager_factory(chain_place,X509ChainManager.X509_CERT)
    return result

    

def load_chain_from_dirs(list_of_dirs):
    """
    A similar approach like above ones but we need
    it for our project because all the time we have 
    different diectories for different certs so may
    need to scan them. The scanning depth is 1 we dont do
    recursive things because we may have some private keys :)
    """
    chain_place = load_certs_from_dirs(list_of_dirs)
    result=chain_manager_factory(chain_place,X509ChainManager.X509_CERT)
    return result


def load_certs_from_dir(scan_dir):
    """
    Return back a list of X509Cert objects from a direcory
    """
    return load_cert_from_dir(scan_dir,get_all=True)

def load_certs_from_dirs(list_of_dirs):
    """
    Loads the certs from a list of directories
    """
    cert_list = []
    for dir in list_of_dirs:
        tmp_cert=load_cert_from_dir(dir)
        if tmp_cert:
            cert_list.append(tmp_cert)

    return cert_list

def load_cert_from_dir(scan_dir,get_all=False):
    """
    Gets a single cert from a dir. It gets the first one it 
    finds. Therefore donot expect some magic here ...
    """
    from M2Crypto import X509 as x
    import sys
    from imzaci.config import INTERNAL_DB_FILE
    import os

    #firstly we should check if we have some index file that locates
    #the cert of the current directory ...
    if os.path.exists(os.path.join(scan_dir,INTERNAL_DB_FILE)) and not get_all:
        #continue by scanning the file ...
        store=open_internal_db(scan_dir,"r",write_dict=None)
        #print store
        if not store.has_key("cert") or not store['cert']:
            #print "No cert wa found into the INTERNAL_DB_FILE"
            return None
        else:
            cert_path = os.path.join(scan_dir,store['cert'])
            try:
                tmp = x.load_cert(cert_path)
                #print "Loaded cert :",store['cert']
                return X509Cert(tmp)
            except:
                #print "Error when loading ",store['cert']
                return None

    #we continue by scanning
    get_all_certs = []
    possible_certs = glob.glob("".join([scan_dir,"/","*.pem"]))    
    for cert_path in possible_certs:
        try:
            tmp = x.load_cert(cert_path)
            #print "Cert loaded :",cert_path
            if not get_all:
                return X509Cert(tmp)
            else:
                get_all_certs.append(X509Cert(tmp))
        except Exception,e:
            #print "The cert is not valid ",e
            continue
    
    if get_all and not get_all_certs:
        print "No cert was found in that directory"
        return None
    elif get_all and get_all_certs:
        return get_all_certs
    else:
        print "No cert was found in that directory"
        return None


def load_certs_from_dir_rec(root_dir):
    """
    Gets a list of certs from root dir
    by scanning recursively ...
    Not sure if needed ?
    """
    pass

############### STORING METHODS #############################

def store_chain_file(chain_obj,file=None,include_signer=False):
    """
    Stores a chain object into a single .pem file
    """
    pass

def store_chain_dir(chain_obj,chain_dir=None,include_signer=False):
    """
    Store a chain object into a dir in seperated
    .pem objects ...
    """
    pass



if __name__ == "__main__":
    pass
    
