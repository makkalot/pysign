PySign : That is a package that's aim is to provide for coders and packagers
some util to sign and verify their code/packages by using X509 certs and other
sigining algorithms ...

Modules Needed to run the tool :

1.OpenSSL 0.9.7m

2.m2crypto-0.18 (Not present in pardus)
Link : http://chandlerproject.org/pub/Projects/MeTooCrypto/m2crypto-0.18.tar.gz

3.pysqlite-1.1.8a -Api for sqlite 3.x (Not present in pardus,the pardus one is for API 2.x sqlite)
Link: http://initd.org/pub/software/pysqlite/releases/1.1/1.1.8/pysqlite-1.1.8a.tar.gz

4.pycrypto (Present in pardus)


Directories in the project :


chain : That directory includes a certificate chain which was created with openssl tools.The chais is as follow :
	cacert.pem---signs-->cert1.pem----signs--->cert2.pem
	The root cert is cacert.pem,the intermediate one is cert1.pem  and the client one is cert2.pem.All of them are in X.509 format (the format tool supports).

	key1.pem is private key pf cert1.pem :Password is :client1
	key2.pem is private key of cert2.pem :Password is :client2
	
	The cacert.pem's private key is not present.It is not wise to use root cert for signing.


Code packages :

digest : That directory includes classes and methods about computing hashes of the directory files.And some other useful utilities.
sign: Includes the parts thet signing and verification is done
db: The parts about database (file system) operations.The database is stored also here.



	
