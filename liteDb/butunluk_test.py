from digest.Hasher import DigestMan
from initializer import DbCert
from dbMain import LiteDb

from sign.cert import X509Man

dc=DbCert()
sum=dc.selectS("select cert_sum from certs where ce_id=%s"%(7))
#print sum[0][0]
#print dc.get_certData(2)[1:].split()

d=DigestMan()
sum2=d.gen_buf_hash(dc.get_certData(7)[1:])
print sum2
if sum==sum2:
    print "The sum is ok"
else:
    print "The cert was modified"

sum3=open("chain/cert2.pem","r").read()

sum3=d.gen_buf_hash(sum3)

#print sum3

#try to import  it there
c=X509Man()

c.set_from_buf(dc.get_certData(7)[1:])
print c.get_detail()
