import os

#The root of your directory to scan for md5
#TheRoot='svn'


class StructMe(object):

    #The constructor.
    def __init__(self,name):
        #empty for now
        #print "I'm empty for noww"
        
        self.__name=name
        #print os.curdir(str)
        

    #This one will scan all the structure
    def FileStructure(self):
        lall=[] #will be fulled like a buffer for file access
        #for buffer working
        #Seraching recursively...
        for root,dirs,files in os.walk(self.__name):

            #Process the files return a buffer to write to a file the names...
            self.joiner(files,root,lall)#That returns a list of file names...

        if lall:
            return lall
            
                

    def joiner(self,ToScan,root,lall):

        for f in ToScan:
            #Add only those that are in our range...
            fpath=[]
            a='/'

            if root[len(root)-1]!='/':
                root=root+a

            fpath.append(root)
            fpath.append(f)

            st=''.join(fpath)

            lall.append(st)
        #return lall

if __name__=="__main__":
    FSinstance=StructMe(TheRoot)
    FSinstance.FileStructure()







