from sha import sha

class DigestUtil(object):
    MAX_DIGEST_BUFF = 8096
    DEFAULT_DIGEST = "sha1"

    def __init__(self):
        pass

    def digest_from_buffer(buffer):
        """
        Digest the string in the buffer
        """
        digest_handler = sha()
        digest_handler.update(buffer)
        return digest_handler.hexdigest()
    
    #it is static .
    digest_from_buffer = staticmethod(digest_from_buffer)


    def digest_from_file(file,algo=None):
        """
        Digest the data that is into the file
        """
        try:
            digest_file = open(file,"r")
            buffer = digest_file.read(DigestUtil.MAX_DIGEST_BUFF)
            
            if not buffer:
                return None

            digest_handler = sha()
     
            while buffer:
                digest_handler.update(buffer)
                buffer = digest_file.read(DigestUtil.MAX_DIGEST_BUFF)
            
            digest_file.close()
            return digest_handler.hexdigest()

        except IOError,e:
            print e
            return None

    #yes it is ...
    digest_from_file = staticmethod(digest_from_file)

if __name__ == "__main__":
    pass

