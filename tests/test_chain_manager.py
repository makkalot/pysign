import os 
from imzaci.cert.chain_manager import X509ChainManager,ChainValidationException
from imzaci.cert.cert_tools import load_certs_from_dirs

list_of_cert_dirs={
        "0":"/home/makkalot/code_repo/my_git/pysign/imzaci/chain/child",
        "3":"/home/makkalot/code_repo/my_git/pysign/imzaci/chain/my-ca",
        "2":"/home/makkalot/code_repo/my_git/pysign/imzaci/chain/inter1",
        "1":"/home/makkalot/code_repo/my_git/pysign/imzaci/chain/inter2"
        }

def util_is_chain_valid(list_of_cert_dirs):
    """
    Very simple util to check if current chain is valid
    it doesnt check the internals of the certs.It sorts the 
    list_of_cert_dirs keys and inceremnts one by one and sees
    if one of the parts in the chain are missing
    """
    if not list_of_cert_dirs or len(list_of_cert_dirs)==1:
        return False

    chain_keys = list_of_cert_dirs.keys()
    chain_keys.sort()
    
    next_index = int(chain_keys[0])
    for chain_index in chain_keys:
        if next_index != int(chain_index):
            return False
        next_index = int(chain_index) + 1

    return True

def util_create_random_chain(list_of_cert_dirs):
    import random
    final_cert_dict = {}
    random_length = random.randint(0,len(list_of_cert_dirs.keys())) 
    for index in xrange(random_length):
        random_index = random.randint(0,len(list_of_cert_dirs.keys())-1)
        final_cert_dict[str(random_index)] = list_of_cert_dirs[str(random_index)] 

    #return it back to the util
    return final_cert_dict

def test_util_create_random_chain():
    global list_of_cert_dirs
    for count in xrange(100):
        chain=util_create_random_chain(list_of_cert_dirs)
        util_is_chain_valid(chain)

def do_chain_pack_exist(list_of_cert_dirs):
    for dir in list_of_cert_dirs.values():
        if not os.path.exists(dir):
            return False

    return True

class TestX509ChainManager(object):
    """
    Testing the chain manager here
    """
    def __init__(self):
        """
        The constructor
        """
        global list_of_cert_dirs
        self.constant_list_of_dirs = list_of_cert_dirs
        if not do_chain_pack_exist(self.constant_list_of_dirs):
            raise Exception("You dont have the test dirs run ssl_util to create them")

    def test_load_chain(self):
        """
        The loader place
        #I think it is same with test_create_chain 
        """
        pass

    def test_create_chain(self):
        """
        Creating chain test
        """
        test_count = 10000

        for c in xrange(test_count):
            try:
                cm = X509ChainManager()
                rand_dict = util_create_random_chain(self.constant_list_of_dirs)
                #print "Testing case is ",rand_dict
                is_valid = util_is_chain_valid(rand_dict)
                chain_place = load_certs_from_dirs(rand_dict.values())
                result=cm.load_chain(chain_place,cm.X509_CERT)
                result=cm.create_chain()
                #print "Compare em %s --- %s"%(result,is_valid)
            except ChainValidationException:
                result = False

            assert result == is_valid
            #simple test for hash nthing compared
            x=cm.get_chain_hash()
            #print x

            if c%1000==0:
                print "The %d of the tests are completed "%(c)


if __name__ == "__main__":
    #print util_is_chain_valid(list_of_cert_dirs)
    pass

