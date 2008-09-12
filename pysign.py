""" Module to call the others"""

import getopt
import sys
import os
import string

#custom modules
from liteDb.lister import list_chain
from liteDb.initializer import DbCert
from sign.tryOverride import pkcs7Work
from digest.Hasher import DigestMan
from digest.cryptUtility import Cutil

def usage():
    """ Helper method shows the main usage"""
    
    help="""Program Usage :
            --listall :Lists all chains
            --list [chain name] :Lists proper chain or all if no chain name given
            --sign [file_name] [keyplace] [certs..] "Signs a file ;key is private key
            cert is certificate(s) that should be included in the sign"
            --verify  [file] [signature_place]:Verifies the directory
            --delete [chain_name] :Deletes the chain in db
            --update [chain_name] [trust degree]: Changes the trust degree of a chain
            --import [alias] [chain(s)]: Import the given chain to db
            --hash [root dir] : Computes all the sums that are in dir and stores in a file with same name as root_dir 
            --initdb :Deletes all the things in db and returns a fresh copy of it
            --showsigner [signature_file] :Prints the chain that is in the signature
            --help :Prints that screen
            
            """
    print help
    


def main(argv):
    """ The main arguments passed"""
    try:
        opts,args=getopt.getopt(argv, "", ["help","showsigner=","initdb","listall","list=","sign=","verify=","delete=","update=","import=","hash=","help"])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
        
    for opt,arg in opts:
        #listing a proper chain
        if opt in ("--list"):
            
            if args:
                usage()
                sys.exit(2)
            else:
                if not list_chain(arg):
                    print "No available chain use --listall"
                    sys.exit(2)
                    
                print "Chain loaded look at your browser (Firefox)"
                    
        #Listing all chains:
        elif opt in ("--listall"):
            if args:
                usage()
                sys.exit(2)
            
            else:
                dc=DbCert()
                res=dc.list_chains()
                if not res:
                    print "No chains in db"
                    sys.exit(2)
                    
                else:
                    print res
                    
        #signing a document            
        elif opt in ("--sign"):
            if not args or len(args)<2:
                usage()
                sys.exit(2)
            
            if not os.path.exists(arg):
                print "Provide a valid file to sign"
                sys.exit(2)
                
            arg=Cutil.file_operator(arg, op=0)
            
            if arg==-1 or not arg: 
                sys.exit(2)
            
            #string.strip(arg)
            #dg=DigestMan()
            #print dg.gen_buf_hash(arg) 
               
            p7=pkcs7Work()
            p7.make_sign(args[0],args[1:], arg,"signature.sig")
            sys.exit(0)
            
        #verifying a signature    
        elif opt in ("--verify"):
            if not args:
                usage()
                sys.exit(2)
            
            if not os.path.exists(arg):
                print "Provide a valid file to sign"
                sys.exit(2)
            
                
            arg=Cutil.file_operator(arg, op=0)
            
            if arg==-1 or not arg: 
                sys.exit(2)
            #string.strip(arg)
            
            #dg=DigestMan()
            #print dg.gen_buf_hash(arg)
                
            p7=pkcs7Work()
            #print args[0]
            if p7.verify_sign(arg, args[0]):
                print "Verification succesful"
                
            sys.exit(0)
            
        #importing a chain into db    
        elif opt in ("--import"):        
            dc=DbCert()
            
            if not args:
                usage()
                sys.exit(2)
                
            else:
                if not dc.import_chain(args,arg):
                    print "Chain insertion Failed"
                else:
                    print "Chain inserted into database"
                    
                sys.exit(0)
        
        #deleting a chain from the db        
        elif opt in ("--delete"):
            if args:
                usage()
                sys.exit(2)
            
            dc=DbCert()
            if dc.delete_chain(arg):
                print "Chain deleted succesfully"
            else:
                print "Chain deletion can not be completed"
        
        #updating the trust degreee        
        elif opt in ("--update"):
            if not args or len(args)>1:
                usage()
                sys.exit(2)
                
            dc=DbCert()
            if dc.change_trust(arg, int(args[0])):
                print "Chain trust degree changed"
                
            else:
                print "Chain degree changing failed"
                
            
            sys.exit(0)
            
        elif opt in ("--hash"):
            if args:
                usage()
                sys.exit(2)
                
            dg=DigestMan()
            if dg.store_hash(arg)==True:
                print "Now you can sign the sum file"
                
            else:
                print "Hash computing failed"
                
            sys.exit(0)
            
        elif opt in ("--initdb"):
            dc=DbCert()
            if not dc.c_tables():
                """ Initialization process failed"""
                
            sys.exit(0)
            
        
        elif opt in ("--showsigner"):
            if args:
                usage()
                sys.exit(2)
                
            p7=pkcs7Work()
            if not p7.print_signers(arg):
                "The chain into signature can not be shown"
            
            sys.exit(0)
            
        elif opt in ("--help"):
            usage()
            sys.exit(2)
        
             
            
                    
        
    #print opts
    #print args
        
    
    
if __name__=="__main__":
    main(sys.argv[1:])