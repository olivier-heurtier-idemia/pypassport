# Copyright 2009 Jean-Francois Houzard, Olivier Roger
#
# This file is part of pypassport.
#
# pypassport is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# pypassport is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with pyPassport.
# If not, see <http://www.gnu.org/licenses/>.

# See https://www.openssl.org/docs/manmaster/man1/openssl.html
# and https://www.openssl.org/docs/man1.1.1/man1/

import os, shutil
import tempfile
from contextlib import ExitStack
import subprocess
from pypassport import hexfunctions
from pypassport.logger import Logger

class OpenSSLException(Exception):
    def __init__(self, *params):
        Exception.__init__(self, *params)

class _TemporaryFileWrapper:
    def __init__(self, name):
        self.name = name
    def __enter__(self):
        return self
    def __exit__(self, exc, value, tb):
        os.unlink(self.name)
def TempFile(data=b' '):
    with tempfile.NamedTemporaryFile(delete=False) as t:
        t.file.write(data)
        t.file.close()
        return _TemporaryFileWrapper(t.name)

class OpenSSL(Logger):
    
    def __init__(self, config="", opensslLocation="openssl"):
        Logger.__init__(self, "OPENSSL")
        self._opensslLocation = opensslLocation
        self._config = config

    def _getOpensslLocation(self):
        return self._opensslLocation


    def _setOpensslLocation(self, value):
        self._opensslLocation = value

    def getPkcs7SignatureContent(self, p7b):
        """
        Return the data contained in the pkcs#7 signature.
        @param p7b: A pkcs#7 signature in der format
        @return: The data contained in the signature
        """
        with TempFile(p7b) as f:
            return self._execute("smime -verify -in " + f.name + " -inform DER -noverify")
            
    def verifyX509Certificate(self, certif, trustedCertif):
        """
        Verify the x509 certificate.
        @param certif: The certificate to verify
        @param trustedCertif: The directory containing the root certificates
        @return: True if correct
        """
        with TempFile(certif) as f:
            data = self._execute("verify -CApath "+trustedCertif+" "+f.name)
            data = data.replace(f.name.encode('latin-1')+b": ", b"")

        if data[:2] == b"OK":
            return True
        raise OpenSSLException(data.strip())
    
    def retrievePkcs7Certificate(self, derFile):
        """ 
        Retrieve the certificate from the binary string, and returns it
        into a human readable format.
        @param derFile: The certificate in der format
        @return: The certificate in a human readable format
        """
        with TempFile(derFile) as f:
            return self._execute("pkcs7 -in "+f.name+" -inform DER -print_certs -text")
            
    def retrieveRsaPubKey(self, derFile):
        """ 
        Transform the rsa public key in der format to pem format" 
        @param derFile: A rsa public key in der format
        @return: The rsa public key in pem formar
        """
        
        with TempFile(derFile) as f:
            return self._execute("pkey -in "+f.name+" -inform DER -pubin -text")
            
    def retrieveECPubKey(self, derFile):
        """ 
        Transform the EC public key in der format to pem format" 
        @param derFile: A EC public key in der format
        @return: The EC public key in pem format
        """
        
        with ExitStack() as stack:
            f_der = stack.enter_context(TempFile(derFile))
            f_pem = stack.enter_context(TempFile())
            pem = self._execute("ec -in "+f_der.name+" -inform DER -pubin -outform PEM -out "+f_pem.name)
            with open(f_pem.name, "rb") as pem:
                return pem.read()

    def verifyECSignature(self, pubK, signature, challenge):
        """ 
        Verify the EC signature
        @param pubK: A EC public key in der format
        @param signature: The signature to verify with the pubKey, in DER format
        @param challenge: The challenge that was signed (hashed value of the challenge)
        @return: The data contained in the signature
        """
        self._execute("version")
        with ExitStack() as stack:
            f_pubK = stack.enter_context(TempFile(pubK))
            f_signature = stack.enter_context(TempFile(signature))
            f_challenge = stack.enter_context(TempFile(challenge))
            ret = self._execute("pkeyutl -keyform DER -inkey "+f_pubK.name+" -sigfile "+f_signature.name+" -verify -pubin -in "+f_challenge.name, True)
            if ret.find(b'Verified Successfully') > 0:
                return True
            return False

    def retrieveSignedData(self, pubK, signature):
        """ 
        Retrieve the signed data from the signature
        @param pubK: A RSA public key in der format
        @param signature: The signature to verify with the pubKey
        @return: The data contained in the signature
        """
        
        #Verify if openSSL is installed
        self._execute("version")
        with ExitStack() as stack:
            f_pubK = stack.enter_context(TempFile(pubK))
            f_signature = stack.enter_context(TempFile(signature))
            f_res = stack.enter_context(TempFile())
            self._execute("rsautl -inkey "+f_pubK.name+" -in "+f_signature.name+" -verify -pubin -raw -out "+f_res.name+" -keyform DER", True)
            with open(f_res.name, "rb") as sig:
                data = sig.read()
        
        return data
    
    def signData(self, sodContent, ds, dsKey):
        bkup = self._opensslLocation
        
        p12 = self.toPKCS12(ds, dsKey, "titus")
        dsDer = self.x509ToDER(ds)
            
        with ExitStack() as stack:
            f_sodContent = stack.enter_context(TempFile(sodContent))
            f_p12 = stack.enter_context(TempFile(p12))
            f_dsDer = stack.enter_context(TempFile(dsDer))
            f_signed = stack.enter_context(TempFile())
            try:            
                self._opensslLocation = "java -jar "
                cmd = "createSod.jar --certificate "+f_dsDer.name+" --content "+f_sodContent.name+" --keypass titus --privatekey "+f_p12.name+" --out "+f_signed.name
                res = self._execute(cmd, True)
            finally:
                self._opensslLocation = bkup
            with open(f_signed.name, "rb") as f:
                res = f.read()
            return res
            
    
    def genRSAprKey(self, size):
        """ 
        Return an RSA private key of the specified size in PEM format.
        """
        return self._execute("genrsa " + str(size))
    

    
    def genRootX509(self, cscaKey, validity="",  distinguishedName=None):
        """
        Generate a x509 self-signed certificate in PEM format
        """
        with TempFile(cscaKey) as f:
            if distinguishedName:
                subj = distinguishedName.getSubject()
            else:
                subj = DistinguishedName(C="BE", O="Gouv", CN="CSCA-BELGIUM").getSubject()
            
            cmd = "req -new -x509 -key "+f.name+" -batch -text"
            if self._config:
                cmd += " -config " + self._config
            if subj:
                cmd += " -subj " + subj
            if validity:
                cmd += " -days " + str(validity)
            return self._execute(cmd)
    
    def genX509Req(self, dsKey, distinguishedName=None):
        """
        Generate a x509 request in PEM format
        """
        with TempFile(dsKey) as f:
            if distinguishedName:
                subj = distinguishedName.getSubject()
            else:
                subj = DistinguishedName(C="BE", O="Gouv", CN="Document Signer BELGIUM").getSubject()
            
            cmd = "req -new -key "+f.name+" -batch"
            if self._config:
                cmd += " -config " + self._config
            if subj:
                cmd += " -subj " + str(subj)
            return self._execute(cmd)
            
    def signX509Req(self, csr, csca, cscaKey, validity=""):
        """
        Sign the request with the root certificate. Return a x509 certificate in PEM format
        
        @param csr: The certificate request
        @param csca: The root certificate
        @param cscaKey: The CA private key
        @param validity: The validity of the signed certificate
        """
        with ExitStack() as stack:
            f_csr = stack.enter_context(TempFile(csr))
            f_csca = stack.enter_context(TempFile(csca))
            f_cscaKey = stack.enter_context(TempFile(f_cscaKey))
            cmd = "ca -in "+f_csr.name+" -keyfile "+f_cscaKey.name+" -cert "+f_csca.name+"  -batch"
            if self._config:
                cmd += " -config " + self._config
            if validity:
                cmd += " -days " + str(validity)
            return self._execute(cmd)
            
    def genCRL(self, csca, cscaKey):
        """ 
        @param csca: The root certificate
        @param cscaKey: The CA private key
        """
        
        with ExitStack as stack:
            f_csca = stack.enter_context(TempFile(csca))
            f_cscaKey = stack.enter_context(TempFile(f_cscaKey))
            cmd = "ca -gencrl -cert "+f_csca.name+" -keyfile "+f_cscaKey.name
            if self._config:
                cmd += " -config " + self._config
            return self._execute(cmd)
            
    def revokeX509(self, cert, csca, cscaKey):
        """ 
        @param csca: The root certificate
        @param cscaKey: The CA private key
        """
        with ExitStack() as stack:
            f_cert = stack.enter_context(TempFile(cert))
            f_csca = stack.enter_context(TempFile(csca))
            f_cscaKey = stack.enter_context(TempFile(f_cscaKey))
            cmd = "ca -revoke "+f_cert.name+" -cert "+f_csca.name+" -keyfile "+f_cscaKey.name
            if self._config:
                cmd += " -config " + self._config
            return self._execute(cmd, True)

    
    def toPKCS12(self, certif, prK, pwd):
        """  
        Return a RSA key pair under the PKCS#12 format.
        PKCS#12: used to store private keys with accompanying public key certificates, protected with a password-based symmetric key
        """
        with ExitStack() as stack:
            f_certif = stack.enter_context(TempFile(certif))
            f_prK = stack.enter_context(TempFile(prK))
            return self._execute("pkcs12 -export -in "+f_certif.name+" -inkey "+f_prK.name+" -passout pass:" + pwd)
            
    def x509ToDER(self, certif):
        with TempFile(certif) as f:
            return self._execute("x509 -in "+f.name+" -outform DER")
            
    def prRSAToDERPb(self, prKey):
        """ 
        Retrieve the corresponding DER encoded public key fron the given a RSA private key
        """
        with TempFile(prKey) as f:
            return self._execute("rsa -pubout -in "+f.name+" -outform der")
            
    def RSAKeyToText(self, key):
        """ 
        Convert a key to its text format
        """
        with TempFile(key) as f:
            return self._execute("rsa -text -in "+f.name)
            
    def crlToDER(self, crl):
        with TempFile(crl) as f:
            return self._execute("crl -inform PEM -in "+f.name+" -outform DER")

    def _execute(self, toExecute, empty=False):
        
        cmd = self._opensslLocation + " " + toExecute
        self.log(cmd)

        res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = res.stdout.read()
        err = res.stderr.read()
        
        if ((not out) and err and not empty):
            raise OpenSSLException(err)
        
        if(err):
            self.log(err)
        
        return out
    
    def _isOpenSSL(self):
        cmd = "version"
        try:
            return self._execute(cmd)
        except OpenSSLException as msg:
            return False
                  
    def printCrl(self, crl):
        with TempFile(crl) as f:
            cmd = 'crl -in '+f.name+' -text -noout -inform DER'
            return self._execute(cmd)

    location = property(_getOpensslLocation, _setOpensslLocation, None, None)
    
        