from imzaci.util.ssl_util import run_ssl_nointeract

def get_cert_from_signature(signature_file):
    string_to_run = "pkcs7 -in %s -print_certs"%(signature_file)
    try:
        result = run_ssl_nointeract(string_to_run)
        #print "The result from ssl is ",result
        return result[0]

    except Exception,e:
        print "Errrorro when eexecuting the str ",e
        return None
