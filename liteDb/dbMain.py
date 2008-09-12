#from pysqlite2 import dbapi2 as sqlite
import sqlite

class LiteDb(object):
    """ Conducts the basic operation of sqlite db"""
    
    def __init__(self,dbname):
        """ Just creates a new conneciton"""
        self.__conn=sqlite.connect(dbname)
        self.__dbname=dbname
        
    def renew_conn(self):
        self.closeConn()
        self.__conn=sqlite.connect(self.__dbname)
        
        
    def updateS(self,query):
        """ Executes some query that changes the db like insert update delete"""
        
        try :
            self.__cursor=self.__conn.cursor()
            res=self.__cursor.execute(query)
            
            self.__cursor.close()
            self.__conn.commit()
            
            if res:
                return -1
            else:
                return 1
            
            
        except sqlite.DatabaseError,e:
            print "Database error occured :",e
            return -1
            
    def selectS(self,query,nq="all"):
        """ Executes statements that pull data from DBlite
        qn stands for numbre of queries may be fetchall or fetchone
        depends on the result that user expects"""
        
        try :
            #print query 
            self.__cursor=self.__conn.cursor()
            self.__cursor.execute(query)
            
            
            if nq!="all":
                res=self.__cursor.fetchone()
                #print res[0].encode()
                
            else:
                res=self.__cursor.fetchall()
                #print res[0][0].encode()    
            
            self.__cursor.close()
                    
            if res:
                return res
            else:
                return None
            
            
        except sqlite.DatabaseError,e:
            print "Database error occured :",e
            return -1
        
            
        
    
    def closeConn(self):
        """ Close the opened conection for all class"""
        self.__conn.close()
        
        
if __name__=="__main__":
    db=LiteDb("imza")
    sqlI="""insert into person values(null,26,\'rman\')"""
    #print db.updateS(sqlI)
    selectQ="""select * from chains"""
    #selectQ="""select * from person"""
    print db.selectS(selectQ)
    db.closeConn()
    
    del db
        