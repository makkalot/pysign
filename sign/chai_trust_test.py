""" Trying the data structures.."""

certs=[['issuer1','client1','cert1Data'],
       ['issuer2','issuer1','cert2Data'],
       ['root','issuer2','cert3Data'],
       ['fakeroot','issuer','fakedata']
       ]
#['root','root','cert4Data']
#['issuer2','issuer1','cert2Data'],


cert_stack=[]

#Nothing to find at the beginning
found=False


for i in certs:
   
    if i[0]==i[1]:
        print "The root Ca is :%s"%(i[0])
        cert_stack.append(certs.pop(certs.index(i)))
        
        find=cert_stack[0][0]
        found=True
        
        break
    
if not found: # So we should choose a starting point
    issuer_list=[i[0] for i in certs]
    sub_list=[i[1] for i in certs]
    
    for i in issuer_list:
        if not i in sub_list:
            print "The starting point is :%s"%(i)
            found=True
            find=i #The next issuer to search
            
            break # No need to stay anymore

#print cert_stack
#print "The issuer to find : %s"%(find)

while found :
    
    #Before enter set it
    found=False
    
    for cert in certs: 
        if find==cert[0]:
            
            find = cert[1]
            found = True
            #Remove from the list
            cert_stack.append(certs.pop(certs.index(cert)))
            break #out of the loop
    
    if not certs:
        found = False
        
if certs:
    print "The chain can not be constructed "
    print "Remaining :%s"%(certs)
    del cert_stack
    
else :
    print "The cert chain is as follow:"
    print cert_stack
        
#print cert_stack     
            
    
    




        
    
    

