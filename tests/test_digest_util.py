#Test the digest stuff here
from imzaci.digest.digest_util import DigestUtil

class TestDigestUtil(object):

    def test_digest_from_buffer(self):
        digest_str = "digestme"
        d_str=DigestUtil.digest_from_buffer(digest_str)

        #create a tmo file for test purposes
        test_file_name = "test.txt"
        test_file = open(test_file_name,"w")
        test_file.write(digest_str)
        test_file.close()
        
        #print "Our final str is :",d_str
        #print "The other str is :",self.__run_sha1_sum(test_file_name)
        assert d_str == DigestUtil.run_sha1_sum(test_file_name)
        import os
        os.remove(test_file_name)
    
    def test_digest_from_file(self):
        test_file_name = "test.txt"
        self.__create_large_file(test_file_name)
        d_str=DigestUtil.digest_from_file(test_file_name)
         
        #print "Our final str is :",d_str
        #print "The other str is :",self.__run_sha1_sum(test_file_name)
        
        assert d_str == DigestUtil.run_sha1_sum(test_file_name)
        import os
        os.remove(test_file_name)
  
    def __create_large_file(self,file_name):
        ftest = open(file_name,"w")
        for i in range(0,100):
            ftest.write("fooman"*100000)

        ftest.close()


if __name__ == "__main__":
    pass

