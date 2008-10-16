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

    def get_complete_list(base_dir,walk_list):
        """
        Returns back the final list for that directory
        what we need here is a dict structure in
        self.__name:[listo_of_sorted_files]
        """
        final_dict = {
                base_dir : []
                }
        #get the list
        for f_path in walk_list:
            split_dir = os.path.split(f_path)
            #is it in a subdir ?
            if split_dir[0] == os.path.split(base_dir)[0]:
                final_dict[base_dir].append(split_dir[1])
            else:
                #if it is ?
                get_sub_dir = split_dir[0].split(base_dir)
                if len(get_sub_dir)==2:                    
                    if get_sub_dir[1].startswith("/"):
                        get_sub_dir[1]= get_sub_dir[1][1:]
                    tmp_str = os.path.join(get_sub_dir[1],split_dir[1])
                    final_dict[base_dir].append(tmp_str)
        #we want to get the same hash every time
        final_dict[base_dir].sort()
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






