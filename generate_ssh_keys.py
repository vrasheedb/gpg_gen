# -*- coding: utf-8 -*-
"""
Generate RSA pair and encrypt private key before outputting
"""

# import python lib

from __future__ import absolute_import, unicode_literals

import_error = ''

try:
    import paramiko
    import io
    import gnupg
    import subprocess
    from pprint import pprint
    IMPORT = True
except Exception as e :
    IMPORT = False
    import_error = e


class keyBuilder:
    def __init__(self):
        self.test = "success"
        return

    def generate_RSA(self):
        out = io.StringIO()
        key = paramiko.RSAKey.generate(4096)
        key.write_private_key(out)
        pub_key = key.get_base64()
        priv_key = out.getvalue()
        return priv_key, pub_key

    # NOTE: Need to configure GPG home location using jinja 
    def gpg_encrypt(self, data):
        home = '/Users/vrasheed/.gnupg' 
        gpg = gnupg.GPG(gnupghome=home)
        gpg.encoding = 'utf-8'
        encrypted_data = gpg.encrypt(data, 'oya_uni')
        ret = str(encrypted_data)
        return ret
    
    def replace_keys(self):
        priv, pub = self.generate_RSA()
        # Encrypt secrets
        priv_enc = self.gpg_encrypt(priv)
        ret = priv, pub, priv_enc
        return ret
    
    def encrypt_msg(self, data):
        ret = self.gpg_encrypt(data)
        return ret

    def decrypt_msg(self, data):
        home = '/Users/vrasheed/.gnupg' 
        gpg = gnupg.GPG(gnupghome=home)
        gpg.encoding = 'utf-8'
        print('Decrypted')
        ret = str(gpg.decrypt(data, passphrase='KMT1986$'))
        return ret

    def main(self):

        test = self.replace_keys()

        return test

keyBuilder = keyBuilder()

#pprint(keyBuilder.main())
# Need to add arguments 
test = keyBuilder.encrypt_msg("TESTING")
pprint(test)
pprint(keyBuilder.decrypt_msg(test))

if __name__ == "__main__":
    keyBuilder.main()
