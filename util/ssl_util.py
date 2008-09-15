import subprocess

MY_STORE = "/home/makkalot/mygits/pysign/imzaci/chain"
SSL_EXECUTABLE = "openssl"
SSL_CONF = "openssl.cnf"
TEMPLATE_CNF = "template.cnf"

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
    
def create_new_request(private_key_file=None,request_file=None,days=None):
    """
    New request 
    """
    if not private_key_file:
        private_key_file = "newkey.pem"
    if not request_file:
        request_file = "newreq.pem"
    if not days:
        days = "365"

    run_string = "req -config %s -new -keyout %s -out %s -days %s"%(SSL_CONF,private_key_file,request_file,days)
    run_ssl_command(run_string.strip())
    print "The request is saved under :%s "%(MY_STORE+"/"+request_file)
    print "The private key is under :%s "%(MY_STORE+"/"+private_key_file)

def create_new_ca(ca_key_name=None,ca_days=None,ca_cert=None):
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

    print "Enter the name of the directory to store the CA :"
    dir_name = raw_input()
    ca_path = "".join([MY_STORE,"/",dir_name])
    
    if os.path.exists(ca_path):
        print "The dir already exists"
        return
    else:
        #some initializations
        os.mkdir(ca_path)
        os.mkdir(ca_path+"/newcerts")
        os.mkdir(ca_path+"/private")
        os.mkdir(ca_path+"/crl")
        os.mkdir(ca_path+"/certs")
        tmp=open(ca_path+"/index.txt","w")
        tmp.close()
        tmp=open(ca_path+"/serial","w")
        tmp.write("00")
        tmp.close()
    #set the conf file for that CA in its own place
    if not set_ssl_cnf(dir_name,ca_cert,ca_key_name):
        print "Error during setting the eocnfiguration file for CA"
        return

    config_place = "".join([ca_path,"/",SSL_CONF])

    REQ="req -config %s"%(config_place)
    CA="ca -config %s"%(config_place)
    
    #firstly create a request
    request_string = "".join([REQ," -new -keyout ",ca_path,"/private/",ca_key_name," -out ",ca_path,"/","ca-req.pem"])            
    run_ssl_command(request_string)

    #then create the self signed cert here
    ca_string = "".join([CA," -out ",ca_path,"/",ca_cert," -days ",ca_days," -batch -keyfile ",ca_path,"/private/",ca_key_name," -selfsign -infiles ",ca_path,"/","ca-req.pem"])
    run_ssl_command(ca_string)
  
def sign_cert(ca_dir_name,request_cert,ca_key_name=None,ca_cert_name=None,days=None,signed_cert=None):
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
    
    ca_path = "".join([MY_STORE,"/",ca_dir_name])
    #here may do sth different later ... like ccheck current dir and etc
    request_cert = "".join([MY_STORE,"/",request_cert])

    if not os.path.exists(ca_path):
        print "The CA directory you supplied doesnt exists"
        return
    
    if not os.path.exists(request_cert):
        print "The request file doesnt exists"
        return
    

    sign_string="ca -policy policy_anything -config %s/%s -cert %s/%s -in %s -keyfile %s/private/%s -days %s -out %s/%s"%(ca_path,SSL_CONF,ca_path,ca_cert_name,request_cert,ca_path,ca_key_name,days,MY_STORE,signed_cert)
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

if __name__ == "__main__":
    #create_new_request()
    #create_new_ca()
    sign_cert("my-ca","newreq.pem")