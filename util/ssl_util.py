import subprocess
import shelve
import dbm
import fcntl


MY_STORE = "/home/makkalot/mygits/pysign/imzaci/chain"
SSL_EXECUTABLE = "openssl"
SSL_CONF = "openssl.cnf"
TEMPLATE_CNF = "template.cnf"
INTERNAL_DB_FILE="internal.db"

def run_ssl_command(run_string):
    """
    Run a new ssl command through the subprocess
    
    """
    args = [SSL_EXECUTABLE]
    args.extend(run_string.split())
    cmd = subprocess.Popen(
            args,
            shell=False,
            cwd=MY_STORE
            )
    cmd.wait()
    
def create_new_request(create_new_dir=None,private_key_file=None,request_file=None,days=None):
    """
    New request 
    """
    if not private_key_file:
        private_key_file = "newkey.pem"
    if not request_file:
        request_file = "newreq.pem"
    if not days:
        days = "365"

    if create_new_dir:
        #create some stuff it is more tidy that way
        import os
        os.mkdir(MY_STORE+"/"+create_new_dir)
        os.mkdir(MY_STORE+"/"+create_new_dir+"/"+"private")
    if not create_new_dir:
        run_string = "req -config %s -new -keyout %s -out %s -days %s"%(SSL_CONF,private_key_file,request_file,days)
    else:
        run_string = "req -config %s -new -keyout %s/private/%s -out %s/%s -days %s"%(SSL_CONF,create_new_dir,private_key_file,create_new_dir,request_file,days)
        
    run_ssl_command(run_string.strip())
    if not create_new_dir:
        print "The request is saved under :%s "%(MY_STORE+"/"+request_file)
        print "The private key is under :%s "%(MY_STORE+"/"+private_key_file)
    else:
        print "The request is saved under :%s "%(MY_STORE+"/"+create_new_dir+"/"+request_file)
        print "The private key is under :%s "%(MY_STORE+"/"+create_new_dir+"/private/"+private_key_file)
        #create a simple indexdb file to know what is where
        tmp_dict={
                'request':request_file,
                'private':private_key_file
                }
        storage=open_internal_db(create_new_dir,"w",tmp_dict)

def initialize_ca_dir(ca_path):
    """
    Some dummy initialization stuff
    """
    import os

    if not os.path.exists(ca_path):
        os.mkdir(ca_path)
    if not os.path.exists(ca_path+"/newcerts"):
        os.mkdir(ca_path+"/newcerts")
    if not os.path.exists(ca_path+"/private"):
        os.mkdir(ca_path+"/private")
    if not os.path.exists(ca_path+"/crl"):
        os.mkdir(ca_path+"/crl")
    if not os.path.exists(ca_path+"/certs"):
        os.mkdir(ca_path+"/certs")
    if not os.path.exists(ca_path+"index.txt"):
        tmp=open(ca_path+"/index.txt","w")
        tmp.close()
    if not os.path.exists(ca_path+"/serial"):
        tmp=open(ca_path+"/serial","w")
        tmp.write("00")
        tmp.close()


def create_new_ca(dir_name=None,ca_key_name=None,ca_days=None,ca_cert=None):
    """
    Creates a new CA for self signed certs
    """
    import os
    if not ca_key_name:
        ca_key_name = "ca-private.pem"

    if not ca_cert:
        ca_cert = "ca-cert.pem"

    if not ca_days:
        ca_days ="365"

    if not dir_name:
        print "Enter the name of the directory to store the CA :"
        dir_name = raw_input()
    
    ca_path = "".join([MY_STORE,"/",dir_name])
    
    if os.path.exists(ca_path):
        print "The dir already exists"
        return
    else:
        #some initializations
        initialize_ca_dir(ca_path)  
    #set the conf file for that CA in its own place
    if not set_ssl_cnf(dir_name,ca_cert,ca_key_name):
        print "Error during setting the eocnfiguration file for CA"
        return
    
    request_file = "ca-req.pem"
    config_place = "".join([ca_path,"/",SSL_CONF])

    REQ="req -config %s"%(config_place)
    CA="ca -config %s -extensions v3_ca"%(config_place)
    
    #firstly create a request
    request_string = "".join([REQ," -new -keyout ",ca_path,"/private/",ca_key_name," -out ",ca_path,"/",request_file])            
    run_ssl_command(request_string)

    #then create the self signed cert here
    ca_string = "".join([CA," -out ",ca_path,"/",ca_cert," -days ",ca_days," -notext -batch -keyfile ",ca_path,"/private/",ca_key_name," -selfsign -infiles ",ca_path,"/",request_file])
    run_ssl_command(ca_string)
    
    #wrte those to the our internal DB
    tmp_dict={
                'request':request_file,
                'private':ca_key_name,
                'cert':ca_cert
                }
    storage=open_internal_db(dir_name,"w",tmp_dict)
  
def sign_cert(ca_dir_name,request_cert,sign_CA=False,ca_key_name=None,ca_cert_name=None,days=None,req_dir=None,signed_cert=None):
    """
    Signs a request cert 
    """
    import os

    
    #santy checks hereeee
    if not ca_key_name:
        ca_key_name = "ca-private.pem"

    if not ca_cert_name:
        ca_cert_name = "ca-cert.pem"

    if not days:
        ca_days ="365"

    if not signed_cert:
        signed_cert = "signed-cert.pem"
    
    #Am i an intermediate CA ?
    if not os.path.exists(MY_STORE+"/ca_dir_name/"+SSL_CONF):
        set_ssl_cnf(ca_dir_name,ca_cert_name,ca_key_name)

    ca_path = "".join([MY_STORE,"/",ca_dir_name])
    #here may do sth different later ... like ccheck current dir and etc
    if not req_dir:
        request_cert = "".join([MY_STORE,"/",request_cert])
    else:
        request_cert = "".join([MY_STORE,"/",req_dir,"/",request_cert])
        
    if not os.path.exists(ca_path):
        print "The CA directory you supplied doesnt exists"
        return
    
    if not os.path.exists(request_cert):
        print "The request file doesnt exists"
        return
    
    if not sign_CA:
        if not req_dir:
            sign_string="ca -policy policy_anything -config %s/%s -cert %s/%s -in %s -keyfile %s/private/%s -days %s -out %s/%s"%(ca_path,SSL_CONF,ca_path,ca_cert_name,request_cert,ca_path,ca_key_name,days,MY_STORE,signed_cert)
        else:
            sign_string="ca -policy policy_anything -config %s/%s -cert %s/%s -in %s -keyfile %s/private/%s -days %s -out %s/%s"%(ca_path,SSL_CONF,ca_path,ca_cert_name,request_cert,ca_path,ca_key_name,days,req_dir,signed_cert)
            #store it also into the internal DB
            open_internal_db(req_dir,"w",{'cert':signed_cert})
    else:
        #if you want your signed cert to sign other certs 
        #it is useful when creating chains
        if not req_dir:
            sign_string="ca -policy policy_anything -config %s/%s -extensions v3_ca -cert %s/%s -in %s -keyfile %s/private/%s -days %s -out %s/%s"%(ca_path,SSL_CONF,ca_path,ca_cert_name,request_cert,ca_path,ca_key_name,days,MY_STORE,signed_cert)
        else:
            sign_string="ca -policy policy_anything -config %s/%s -extensions v3_ca -cert %s/%s -in %s -keyfile %s/private/%s -days %s -out %s/%s"%(ca_path,SSL_CONF,ca_path,ca_cert_name,request_cert,ca_path,ca_key_name,days,req_dir,signed_cert)
            #it will become a new CA intermediate so initialize its content to be a new CA
            initialize_ca_dir(MY_STORE+"/"+req_dir)
            open_internal_db(req_dir,"w",{'cert':signed_cert})


    #run the signing operation
    run_ssl_command(sign_string.strip())


def set_ssl_cnf(ca_dir_name,ca_cert,private_key):
    """
    When creating different CAs we have to play with openssl.cnf file
    that is what we set here ...
    """
    cnf_values = [
            {'dir':'./%s'%(ca_dir_name)},	
            {'certs':'$dir/certs'},
            {'crl_dir':'$dir/crl'},
            {'database':'$dir/index.txt'},
            {'new_certs_dir':'$dir/newcerts'},
            {'certificate':'$dir/%s'%(ca_cert)},
            {'serial':'$dir/serial'},
            {'crlnumber':'$dir/crlnumber'},
            {'crl':'$dir/crl.pem'},
            {'private_key':'$dir/private/%s'%(private_key)},
            {'RANDFILE':'$dir/private/.rand'},
            {'x509_extensions':'usr_cert'},
            {'name_opt':'ca_default'},
            {'cert_opt':'ca_default'},
            {'default_days':'365'},
            {'default_crl_days':'30'},
            {'default_md':'sha1'},
            {'preserve':'no'},
            {'policy':'policy_match'}
            ]
    #store that into a file called .cnf
    try:
        template_file = open("".join([MY_STORE,"/",TEMPLATE_CNF]),"r").read()
        openssl_cnf = open("".join([MY_STORE,"/",ca_dir_name,"/",SSL_CONF]),"w")
        
        #set the string to store
        final_cnf="\n\n[ CA_default ]\n\n"
        for entry in cnf_values:
            final_cnf = "".join([final_cnf,entry.keys()[0],"\t=\t",entry.values()[0],"\n"])

        #write all the stuff ...
        openssl_cnf.write(str(template_file))
        openssl_cnf.write(str(final_cnf))
        openssl_cnf.close()

    except Exception,e:
        print "Error while setting config file for the CA :",e
        return False

    return True

def open_internal_db(dir,mode,write_dict=None):
    """
    There are 2 modes one r and w
    """
    import os
    if not os.path.exists(dir):
        filename=os.path.join(MY_STORE,dir,INTERNAL_DB_FILE)
    else:
        filename=os.path.join(dir,INTERNAL_DB_FILE)

    try:
        handle = open(filename,mode)
    except IOError, e:
        print 'Cannot create status file. Ensure you have permission to write'
        return None

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    internal_db = dbm.open(filename, 'c', 0644 )
    storage = shelve.Shelf(internal_db)
    
    if mode == "w":
        for key,value in write_dict.iteritems():
            storage[key]=value
    elif mode == "r":
        tmp=dict(storage)
        #print tmp
    storage.close()
    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    if mode == "r":
        return tmp
    else:
        return True

#That method is for creating the initial Testing Database so it should be run only once 
def prepare_test_environment():
    
    #The structure of that chains will be ca-->inter1-->inter2-->child
    print "Creating CA press enter to continue ..."
    tmp=raw_input()
    create_new_ca(dir_name="my-ca")
    print "Creating request for inter1 enter to continue"
    tmp=raw_input()
    create_new_request(create_new_dir="inter1",private_key_file="inter1-key.pem",request_file="inter1-req.pem")
    print "Creating request for inter2 enter to continue"
    tmp=raw_input()
    create_new_request(create_new_dir="inter2",private_key_file="inter2-key.pem",request_file="inter2-req.pem")
    print "Creating request for child enter to continue"
    tmp=raw_input()
    create_new_request(create_new_dir="child",private_key_file="child-key.pem",request_file="child-req.pem")
    print "CA signs the request of inter1 which also will be CA"
    tmp=raw_input()
    sign_cert("my-ca","inter1-req.pem",True,req_dir="inter1",signed_cert="inter1-cert.pem")
    
    print "Inter1 signs the request of inter2 which also will be CA"
    tmp=raw_input()
    sign_cert("inter1","inter2-req.pem",True,ca_key_name="inter1-key.pem",ca_cert_name="inter1-cert.pem",req_dir="inter2",signed_cert="inter2-cert.pem")
    print "Inter2 signs the request of child which will not be a CA"
    tmp=raw_input()
    sign_cert("inter2","child-req.pem",False,ca_key_name="inter2-key.pem",ca_cert_name="inter2-cert.pem",req_dir="child",signed_cert="child-cert.pem")
    print "**** Happpy TESTING *****"

if __name__ == "__main__":
    prepare_test_environment()
    #create a child here
    #create_new_request(create_new_dir="db_test",private_key_file="db-key.pem",request_file="db-cert.pem")
    #print open_internal_db("db_test","r")
    #sign_cert("test-ca","db-cert.pem",False,req_dir="db_test",signed_cert="db-signed.pem")
    #create en inter here
    #create_new_request(create_new_dir="inter",private_key_file="inter-key.pem",request_file="inter-cert.pem")
    #create_new_request()
    #create_new_ca()
    #sign_cert("my-ca","inter-cert.pem",True,req_dir="inter",signed_cert="inter-signed.pem")
    #sign_cert("inter","child-cert.pem",False,ca_key_name="inter-key.pem",ca_cert_name="inter-signed.pem",req_dir="child",signed_cert="inter-signed.pem")
    #sign_cert(ca_dir_name,request_cert,sign_CA=False,ca_key_name=None,ca_cert_name=None,days=None,req_dir=None,signed_cert=None):
