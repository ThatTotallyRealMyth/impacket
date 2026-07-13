#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   AD CS certificate enrollment via RPC (MS-ICPR) or Web Enrollment. Added now that we have a PKINIT implementation come through for the NEGOEX/PKU2U implementation
#   Now Impacket has decent/foundational AD-CS support with a pkinit.py implementation alongside this script we can request certs as well as authenticate using them as needed
# TODO:
#      [] Add a -encrypt flag to allow people to decide since if theres a ESC11 vuln endpoint; we would not want to use encryption(which is current default)
#      [] Add the -sid flag to allow people to add/specify a sid to the cert request in case strong binding is being enforced by the CA
#      [] Add additional options
#      [] Add some additional useful functionality from Windows certdump. Potentially some of its more "enumeration" focused features such as dumping templates etc
# Author:
#   Abdul Mhanni

import sys
import re
import logging
import argparse
import base64

from OpenSSL import crypto

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version, LOG
from impacket.dcerpc.v5 import transport, icpr
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_ICPR = uuidtup_to_bin(('91ae6020-9e3c-11cf-8d7c-00aa00c091be', '0.0'))


class CertReq:
    def __init__(self, username, password, domain, target, options):
        self.username = username
        self.password = password
        self.domain = domain
        self.target = target
        self.lmhash = ''
        self.nthash = ''
        self.template = options.template
        self.altName = options.alt_name
        self.caName = options.ca_name
        self.outfile = options.out

        if options.hashes is not None:
            self.lmhash, self.nthash = options.hashes.split(':')

    def generateKey(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        return key

    def generateCSR(self, key, cn, altName=None, filetype=crypto.FILETYPE_PEM):
        req = crypto.X509Req()
        req.get_subject().CN = cn

        if altName is not None:
            req.add_extensions([crypto.X509Extension(b"subjectAltName", False, ("otherName:1.3.6.1.4.1.311.20.2.3;UTF8:%s" % altName).encode())])

        req.set_pubkey(key)
        req.sign(key, "sha256")

        return crypto.dump_certificate_request(filetype, req)

    def generatePFX(self, key, certificate, certType=crypto.FILETYPE_PEM):
        from cryptography.hazmat.primitives.serialization import pkcs12, NoEncryption

        cert = crypto.load_certificate(certType, certificate)
        cryptoKey = key.to_cryptography_key()
        cryptoCert = cert.to_cryptography()

        return pkcs12.serialize_key_and_certificates(name=b'', key=cryptoKey, cert=cryptoCert, cas=None, encryption_algorithm=NoEncryption())

    def savePFX(self, pfxData):
        filename = self.outfile
        if filename is None:
            filename = '%s.pfx' % self.username.replace('$', '')

        with open(filename, 'wb') as f:
            f.write(pfxData)

        LOG.info('Saved certificate and private key to %s' % filename)

    def requestViaRPC(self):
        # Connect to the CA over MS-ICPR (ncacn_np:\pipe\cert)
        LOG.info('Connecting to MS-ICPR endpoint on %s' % self.target)

        stringBinding = r'ncacn_np:%s[\pipe\cert]' % self.target
        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.username, self.password, self.domain,
                                         self.lmhash, self.nthash)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(MSRPC_UUID_ICPR)

        LOG.info('Connected to endpoint: %s' % stringBinding)

        # Generate CSR in DER format for RPC
        key = self.generateKey()
        csr = self.generateCSR(key, self.username, self.altName, crypto.FILETYPE_ASN1)
        LOG.info('Generated CSR for %s' % self.username)

        # Build attributes
        attributes = ['CertificateTemplate:%s' % self.template]
        if self.altName is not None:
            attributes.append('SAN:upn=%s' % self.altName)

        # Submit the request
        LOG.info('Requesting certificate for template %s' % self.template)
        try:
            certificate = icpr.hCertServerRequest(dce, csr, attributes, ca=self.caName)
        except icpr.DCERPCSessionError as e:
            if e.error_code == 0x80070005:
                LOG.error('Access denied. Encryption may be enforced (IF_ENFORCEENCRYPTICERTREQUEST)')
            elif e.error_code == 0x80070057:
                LOG.error('Invalid parameter. Check CA name: %s' % self.caName)
            elif e.error_code == 0x80094800:
                LOG.error('Template "%s" is not supported by this CA' % self.template)
            else:
                LOG.error('Error requesting certificate: %s' % str(e))
            dce.disconnect()
            return

        dce.disconnect()

        # Build and save PFX
        pfxData = self.generatePFX(key, certificate, crypto.FILETYPE_ASN1)
        self.savePFX(pfxData)

        LOG.info('Base64 certificate:\n%s' % base64.b64encode(pfxData).decode('ascii'))

    def requestViaWeb(self):
        # Authenticate to the AD CS web enrollment page via HTTP NTLM
        try:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except ImportError:
            LOG.critical('requests library required for web enrollment: pip install requests')
            return

        try:
            from impacket.httpntlm import ImpacketHttpNtlmAuth

        hashes = None
        if self.lmhash or self.nthash:
            hashes = '%s:%s' % (self.lmhash, self.nthash)

        identity = '%s\\%s' % (self.domain, self.username) if self.domain else self.username
        auth = ImpacketHttpNtlmAuth(identity, password=self.password, hashes=hashes)

        session = requests.Session()
        session.auth = auth
        session.verify = False

        # Generate PEM CSR for web enrollment
        key = self.generateKey()
        csr = self.generateCSR(key, self.username, self.altName, crypto.FILETYPE_PEM).decode('ascii')
        LOG.info('Generated CSR for %s' % self.username)

        # Build the enrollment POST
        certAttrib = 'CertificateTemplate:%s' % self.template
        if self.altName is not None:
            certAttrib += '\r\nSAN:upn=%s' % self.altName

        enrollUrl = 'http://%s/certsrv/certfnsh.asp' % self.target
        LOG.info('Submitting certificate request to %s' % enrollUrl)

        data = {
            'Mode': 'newreq',
            'CertRequest': csr,
            'CertAttrib': certAttrib,
            'FriendlyType': 'Saved-Request Certificate',
            'TargetStoreFlags': '0',
            'SaveCert': 'yes',
        }

        resp = session.post(enrollUrl, data=data)

        if resp.status_code != 200:
            LOG.error('Web enrollment failed with status %d' % resp.status_code)
            return

        # Parse the Request ID from the response HTML
        match = re.search(r'certnew\.cer\?ReqID=(\d+)&', resp.text)
        if match is None:
            # Check for common errors in the response
            if 'denied' in resp.text.lower():
                LOG.error('Certificate request was denied by the CA')
            elif 'pending' in resp.text.lower():
                LOG.warning('Certificate request is pending CA admin approval')
            else:
                LOG.error('Could not find Request ID in response. '
                          'Check template name and permissions.')
                LOG.debug('Response body:\n%s' % resp.text[:2000])
            return

        reqId = match.group(1)
        LOG.info('Request ID is %s' % reqId)

        # Download the issued certificate
        certUrl = 'http://%s/certsrv/certnew.cer?ReqID=%s&Enc=b64' % (self.target, reqId)
        certResp = session.get(certUrl)

        if certResp.status_code != 200:
            LOG.error('Failed to download certificate (status %d)' % certResp.status_code)
            return

        certificate = certResp.content
        LOG.info('Successfully retrieved certificate')

        # Build and save PFX
        pfxData = self.generatePFX(key, certificate, crypto.FILETYPE_PEM)
        self.savePFX(pfxData)


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Request certificates from AD CS "
                                     "via RPC (MS-ICPR) or Web Enrollment (certsrv).")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    enrollment = parser.add_argument_group('enrollment')
    enrollment.add_argument('-template', action='store', required=True, help='Certificate template name (e.g. User, Machine, DomainController)')
    enrollment.add_argument('-ca-name', action='store', default='', help='Certificate Authority name (e.g. CORP-DC-CA)')
    enrollment.add_argument('-alt-name', action='store', default=None, help='Alternative UPN to request in the certificate (SAN)')
    enrollment.add_argument('-out', action='store', default=None, help='Output PFX filename (default: <username>.pfx)')

    method = parser.add_mutually_exclusive_group(required=True)
    method.add_argument('-rpc', action='store_true', help='Request certificate via MS-ICPR (RPC)')
    method.add_argument('-web', action='store_true', help='Request certificate via Web Enrollment (certsrv)')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()


    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    certreq = CertReq(username, password, domain, address, options)

    if options.rpc:
        certreq.requestViaRPC()
    elif options.web:
        certreq.requestViaWeb()


if __name__ == '__main__':
    main()
