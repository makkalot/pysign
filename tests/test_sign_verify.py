from imzaci.sign.sign_verify import *
SIGN_DIRECTORY = "/home/makkalot/code_repo/my_git/pysign/imzaci/chain/signer"
TO_SIGN = "/home/makkalot/Desktop"

def test_sign():
    p7_manager = Pkcs7Signer()
    p7_manager.set_sign_chain(SIGN_DIRECTORY)
    print p7_manager.sign_data(TO_SIGN)
