import os

#The root of your directory to scan for md5
#TheRoot='svn'


class FileList(object):
    """
    The class is for getting back all
    of the file names that are in the given dir
    """
    #The constructor.
    def __init__(self,name):
        self.__name=name

    def walk_through(self):
        """
        Scans the diresctories recursively to get
        the complete list ...
        """
        all=[] #will be fulled like a buffer for file access
        
        #Searching recursively...
        for root,dirs,files in os.walk(self.__name):
            #Process the files return a buffer to write to a file the names...
            if files:
                #print "The root is :",root
                #print "The files are : ",files
                self.__path_joiner(files,root,all)#That returns a list of file names...
        return all
            
                
    def __path_joiner(self,to_scan,root,all):

        for file in to_scan:
            #Add only those that are in our range...
            all.append(os.path.join(root,file))

    def get_complete_list(base_dir,walk_dict):
        """
        Returns back the final list for that directory
        what we need here is a dict structure in
        self.__name:{file_name:sha1_hash}
        """
        final_dict = {
                base_dir : {}
                }
        #get the list
        for f_path,f_hash in walk_dict.iteritems():
            split_dir = os.path.split(f_path)
            #is it in a subdir ?
            if split_dir[0] == os.path.split(base_dir)[0]:
                final_dict[base_dir][split_dir[1]]=f_hash
            else:
                #if it is ?
                get_sub_dir = split_dir[0].split(base_dir)
                if len(get_sub_dir)==2:                    
                    if get_sub_dir[1].startswith("/"):
                        get_sub_dir[1]= get_sub_dir[1][1:]
                    tmp_str = os.path.join(get_sub_dir[1],split_dir[1])
                    final_dict[base_dir][tmp_str] = f_hash
        #we want to get the same hash every time

        #print "The final dict is :",final_dict
        return final_dict

    #lets make it static ...
    get_complete_list=staticmethod(get_complete_list)


from threading import *
import time
import thread

class DirHashHandler(object):
    """
    That class will get the final sha1 sum of the
    requested dir. Finally we should have in our hands 
    a dict in format file_path : sha1sum. The DirHashHandler
    class will spawn a few Threads to do that dir-hashing 
    operation. We have chosen the threads because most of the
    time we do IO based oprations ...
    """

    NUM_OF_THREADS = 4

    def __init__(self,dir_to_hash):
        self.__dir_hash = dir_to_hash
        #get the file list you will be working on
        tmp_flist = FileList(self.__dir_hash)
        self.__file_list = tmp_flist.walk_through()
        #print self.__file_list
        #here we will store all of the stuff
        self.__final_sha_list = {}
        #the conditions to lock the things
        self.__file_list_lock = Condition()
        self.__final_sha_list_lock = Condition()

    def get_final_hash_dict(self):
        """
        Here spawn and do all the stuff
        """
        #will have the therads here for now
        consumers = []
        for i in range(0,self.NUM_OF_THREADS):
            f = FileHasherThread(i,self.__file_list,self.__file_list_lock,self.__final_sha_list,self.__final_sha_list_lock)
            consumers.append(f)

        #let start those threads
        for t in consumers:
            t.start()

        #we will wait until they finish the stuff
        for t in consumers:
            t.join()

        return self.__final_sha_list

    def store_final_hash(self,f_name):
        """
        Stores the final hash to a file that way
        we can sign,verify it ...
        """
        final_hash_list = self.get_final_hash_dict()
        #that is for making the final list without main dir infront of it
        dict_store = FileList.get_complete_list(self.__dir_hash,final_hash_list) 
        try:
            file_to_write = open(f_name,"w")
            #i store it sorted because when having its sha1sum it should be same every time
            sorted_file_keys = dict_store[self.__dir_hash].keys()
            sorted_file_keys.sort()

            for f_name in sorted_file_keys:
                #write every file to be in an esasy format for parsing later
                file_to_write.write("".join([f_name,":",dict_store[self.__dir_hash][f_name],"\n"]))
            file_to_write.close()
        except IOError,e:
            print e
            return False
        return True
    

class FileHasherThread(Thread):
    """
    A simple thread class that computes the hash of a file
    """
    
    def __init__(self,t_id,file_pool,file_pool_lock,finished_pool,finished_pool_lock):
        """
        Initialize the stuff
        """
        Thread.__init__(self)
        self.t_id = t_id
        self.file_pool = file_pool
        #print self.file_pool
        self.file_pool_lock = finished_pool_lock
        self.finished_pool = finished_pool
        self.finished_pool_lock = finished_pool_lock
    
    def run(self):
        """
        The part where computes the sha1 sum
        """
        from imzaci.digest.digest_util import DigestUtil
        import time
        #while we have things to do 
        finish = False
        while 1:
            self.file_pool_lock.acquire()#get the lock
            if len(self.file_pool)>0:
                file_to_process = self.file_pool.pop() #get one
            else:
                finish = True
            self.file_pool_lock.release()
            if finish:
                break

            #print "Digest in thread %d "%(self.t_id)
            #time.sleep(2)

            file_hash = DigestUtil.digest_from_file(file_to_process)
            #it seems you have processed your part you can add it to finished
            self.finished_pool_lock.acquire()
            self.finished_pool[file_to_process] = file_hash
            self.finished_pool_lock.release()



if __name__=="__main__":
    pass
    #place = "/home/makkalot/code_repo/my_git/pysign/imzaci/chain"
    #f = FileList(place)
    #entries = f.walk_through()
    #print entries
    #f_list = FileList.get_complete_list(place,entries)
    #print f_list
    #for e in f_list:
        #print os.path.join(place,e)






