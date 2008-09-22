
def parse_pem_cert(chain_file):
    """
    Finds the -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
    parts in a .pem formatted file and extracts the certs from it
    """
    import string 
    from imzaci.cert.cert import X509Cert

    start_text = "-----BEGIN CERTIFICATE-----"
    end_text = "-----END CERTIFICATE-----"

    cert_objects = []
    cert_buffer = open(chain_file,"r").read()
    stop_index=0
    while True:
        #find the first part
        if stop_index != 0:
            start_index=string.find(cert_buffer,start_text,stop_index+len(end_text))
        else:
            start_index=string.find(cert_buffer,start_text)

        if start_index == -1:
            break
        stop_index = string.find(cert_buffer,end_text,start_index+len(start_text))
        
        if stop_index == -1:
            print "Malformed .pem file cant extract the cert chain from it"
            return None

        #print cert_buffer[start_index:stop_index+len(end_text)]
        
        try:
            current_cert = X509Cert()
            current_cert.set_from_buf(cert_buffer[start_index:stop_index+len(end_text)].strip(),format=0)
            #current_cert.list_info()
            #print "cert_appended"
            cert_objects.append(current_cert) 
        except:
            print "Cert loading error"
    return cert_objects

if __name__ == "__main__":
    pass
    #parse_pem_cert("/home/makkalot/mygits/pysign/imzaci/chain/tek-file/chain.pem")
