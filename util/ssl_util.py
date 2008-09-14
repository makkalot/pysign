import subprocess

MY_STORE = "/home/makkalot/mygits/pysign/imzaci/chain"
SSL_EXECUTABLE = "openssl"
SSL_CONF = "openssl.cnf"

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
   
if __name__ == "__main__":
    create_new_request()

