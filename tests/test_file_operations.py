#Test the file and dir digester
from imzaci.digest.file_operations import FileList
from imzaci.digest.digest_util import DigestUtil
from imzaci.digest.file_operations import DirHashHandler
TEST_DIR = "/home/makkalot/code_repo/my_git/pysign/imzaci/chain"
#TEST_DIR = "/media/disk"
def compute_hash_without_thread(base_dir):
    """
    Because the thread based implementation alway scares me
    i will compare its result with a normal straight implemenattion
    """
    tmp_flist = FileList(base_dir)
    file_list = tmp_flist.walk_through()

    if not file_list:
        return None

    final_dict = {}

    for file_to_process in file_list:
        file_hash = DigestUtil.digest_from_file(file_to_process)
        final_dict[file_to_process] = file_hash

    return final_dict


def test_dir_hash_creator():
    """
    It is a comparison between threadded and straight impl
    """
    straight = compute_hash_without_thread(TEST_DIR)
    #print straight
    for i in range(0,1000):
        dh = DirHashHandler(TEST_DIR)
        threaded = dh.get_final_hash_dict()
        #print threaded
        assert straight.keys().sort() == threaded.keys().sort()
        assert straight.values().sort() == threaded.values().sort()
        if i%100==0:
            print "The %d of tests completed"%(i)

