PisiSign Tool :
Pisi package sign and verification command line tool.More detailed explanation will be added to wiki very soon...

Instalation:
Tool doesnt have a instalation script,because it may be integrated with pisi and package-manager if it is succesfull.

Modules Needed to run the tool :

1.OpenSSL 0.9.7m

2.m2crypto-0.18 (Not present in pardus)
Link : http://chandlerproject.org/pub/Projects/MeTooCrypto/m2crypto-0.18.tar.gz

3.pysqlite-1.1.8a -Api for sqlite 3.x (Not present in pardus,the pardus one is for API 2.x sqlite)
Link: http://initd.org/pub/software/pysqlite/releases/1.1/1.1.8/pysqlite-1.1.8a.tar.gz

4.pycrypto (Present in pardus)


Directories in the project :

example_dir : Is a directory which is used to test if program computes the hashes of files in it.It can be any directory.

chain : That directory includes a certificate chain which was created with openssl tools.The chais is as follow :
	cacert.pem---signs-->cert1.pem----signs--->cert2.pem
	The root cert is cacert.pem,the intermediate one is cert1.pem  and the client one is cert2.pem.All of them are in X.509 format (the format tool supports).

	key1.pem is private key pf cert1.pem :Password is :client1
	key2.pem is private key of cert2.pem :Password is :client2
	
	The cacert.pem's private key is not present.It is not wise to use root cert for signing.


Code packages :

digest : That directory includes classes and methods about computing hashes of the directory files.And some other useful utilities.
sign: Includes the parts thet signing and verification is done
liteDb: The parts about database (sqlite3) operations.The database is stored also here.

main.py: The main module that all operations are combined.


Example usage : All the examples are made with certficates above.

*Showing the help screen :
	makkalot@makkalot-pardus src $ python main.py --help
Program Usage :
            --listall :Lists all chains
            --list [chain name] :Lists proper chain or all if no chain name given
            --sign [file_name] [keyplace] [certs..] "Signs a file ;key is private key
            cert is certificate(s) that should be included in the sign"
            --verify  [file] [signature_place]:Verifies the directory
            --delete [chain_name] :Deletes the chain in db
            --update [chain_name] [trust degree]: Changes the trust degree of a chain
            --import [alias] [chain(s)]: Import the given chain to db
            --hash [root dir] : Computes all the sums that are in dir and stores in a file with same name as root_dir
            --initdb :Deletes all the things in db and returns a fresh copy of it
            --showsigner [signature_file] :Prints the chain that is in the signature
            --help :Prints that screen


*The first thing we should do is to initialize the database (be sure you have the right sqlite3 module installed).
	makkalot@makkalot-pardus src $ python main.py --initdb
	Db exists it's been deleted
	Initialization done...


*After initialization we may want to import a chain into database.It must be a valid chain because tool arises error in that case.We must provide an alias when we import a chain.(Useful for later usage )

	makkalot@makkalot-pardus src $ python main.py --import newChain chain/cacert.pem chain/cert1.pem chain/cert2.pem
	Import process succesfull
	Chain inserted into database

If we enter an invalid chain like : chain/cacert.pem chain/cert2.pem we will get an error.Because cert2.pem was signed by cert1.pem so the chain is not a valid one in that case:

	makkalot@makkalot-pardus src $ python main.py --import newChain chain/cacert.pem chain/cert2.pem
	The chain can not be constructed
	The chain is not valid
	Chain insertion Failed

*You can list to see if the chain was inserted :

	makkalot@makkalot-pardus src $ python main.py --listall
	Chain Name : newChain Trust Degree : trusted
	**************************************************

The trust degree is for sorting the chains we trust,dont trust,and not sure about that.That option will be more useful when integrated with package manager.

*You can list a proper chain. When we invoke the proper action,we should check out browser (Firefox).Because the chain is shown in html pages and cert details are included also. That option is temporary it was added to see the cert details...

	makkalot@makkalot-pardus src $ python main.py --list newChain
	Chain loaded look at your browser (Firefox).

*You can compute the file hashes of a directory,which is one of the main thigs program should do.

	makkalot@makkalot-pardus src $ python main.py --hash example_dir
	All hashes written to file : example_dir.txt
	Now you can sign the sum file

*Sign the previously hashed file.The chain we provide again should be valid one because the checks about that.

	makkalot@makkalot-pardus src $ python main.py --sign example_dir.txt chain/key2.pem chain/cert2.pem chain/cert1.pem chain/cacert.pem
	Enter passphrase:
	The signature saved to :signature.sig

	cert2.pem is the cert for key2.pem. They should be in that order (it is a bug for now will be fixed) 

*Verify the file you signed.The program checks if the chain is in db if it is the verification is made,otherwise it asks user that the cert is not in db ...
	makkalot@makkalot-pardus src $ python main.py --verify example_dir.txt signature.sig
	Chain is already in the database
	The chain  is in db verification continues...
	Verification succesful

	Program just tests if the chain is in db it doesnt control if it has trusted flag.(That will be fixed).

*Before we verify some signature we may want to see signer (certficate )details so :(again shown in browser)

	makkalot@makkalot-pardus src $ python main.py --showsigner signature.sig
	The chain is loaded in your browser (Firefox)


	