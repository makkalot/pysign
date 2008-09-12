""" Explores about the main usage about sqlite python wrapper"""

from pysqlite2 import dbapi2 as sqlite

#if db doesnt exist then it will be created otherwise it will be opened
conn=sqlite.connect("dbtest")

#create a cursor to execute the sql commands
cursor=conn.cursor()

sqlQ="""create table person(id integer primary key AUTOINCREMENT,
                            age integer,
                            name varchar(30))"""

sqlI="""insert into person values(null,25,\'remo\')"""

#print "Comands to be executed are :"
#print sqlQ
#print sqlI

#cursor.execute(sqlQ)
#print cursor.execute(sqlI)

#conn.commit()
print "All actions saved"
#Eger kayededilmesinin istemiyorsak 
#conn.rollback()

#Getting information...
selectQ="""select * from person where id=3"""
res=cursor.execute(selectQ)
#res=res.fetchall()
res=res.fetchone()

if res:
    print res
else:
    print "No result found"





