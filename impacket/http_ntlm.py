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
#   HTTP NTLM Authentication module
# Supports plaintext passwords and NTLM hash pass-the-hash. Negotiate flags and NTLMv1/v2
#   selection are handled by Impacket's getNTLMSSPType1/Type3 internally.
#
#   Implements the standard HTTP NTLM three-leg handshake transparently
#   over keep-alive connections.
#
# Author:
#   Abdul Mhanni
import base64
import re

from requests.auth import AuthBase

from impacket import LOG
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3


class ImpacketHttpNtlmAuth(AuthBase):
    # requests.auth.AuthBase implementation using Impacket's NTLM library.
    # Provides Impacket's full NTLM capability over HTTP, including
    # pass-the-hash and NTLMv1/v2 selection.

    def __init__(self, username, password='', hashes=None, use_ntlmv2=True):
        # Parse the identity string into domain and username
        # Accepts 'DOMAIN\\user', 'DOMAIN/user', 'user@domain', or plain 'user'
        self.domain, self.username = self._parseIdentity(username)
        self.password = password
        self.use_ntlmv2 = use_ntlmv2

        # Parse NTLM hashes if provided
        self.lmhash = b''
        self.nthash = b''
        if hashes is not None:
            self._parseHashes(hashes)

    def _parseIdentity(self, identity):
        # Parse 'DOMAIN\\user' or 'user@domain' into (domain, username)
        # Falls back to domain='.' if no separator is found
        if '\\' in identity:
            domain, username = identity.split('\\', 1)
        elif '/' in identity:
            domain, username = identity.split('/', 1)
        elif '@' in identity:
            username, domain = identity.rsplit('@', 1)
        else:
            domain = '.'
            username = identity
        return domain, username

    def _parseHashes(self, hashes):
        # Parse 'LMHASH:NTHASH' hex string into raw bytes
        try:
            lmhex, nthex = hashes.split(':')
        except ValueError:
            raise ValueError("Hashes must be in LMHASH:NTHASH format. "
                             "Use ':NTHASH' or 'aad3b435b51404eeaad3b435b51404ee:NTHASH' "
                             "for NT-only authentication.")

        self.lmhash = bytes.fromhex(lmhex) if lmhex else b''
        self.nthash = bytes.fromhex(nthex) if nthex else b''

    def _buildNegotiateMessage(self):
       
        negotiate = getNTLMSSPType1(
            workstation='',
            domain=self.domain,
            signingRequired=False,
            use_ntlmv2=self.use_ntlmv2,
        )
        return negotiate.getData()

    def _buildAuthenticateMessage(self, challengeBase64):
        # Parse the server's Type 2 (Challenge) and build the
        # Type 3 (Authenticate) response using getNTLMSSPType3
        challengeRaw = base64.b64decode(challengeBase64)
        negotiateMessage = self._buildNegotiateMessage()

        authMsg = getNTLMSSPType3(
            type1=negotiateMessage,
            type2=challengeRaw,
            user=self.username,
            password=self.password,
            domain=self.domain,
            lmhash=self.lmhash,
            nthash=self.nthash,
            use_ntlmv2=self.use_ntlmv2,
        )
        return authMsg.getData()

    def _extractChallengeFromHeader(self, response):
        # Extract the base64 NTLM challenge token from the server
        # WWW-Authenticate header after the Type 1 exchange
        authHeader = response.headers.get('WWW-Authenticate', '')

        match = re.search(r'(?:NTLM|Negotiate)\s+([a-zA-Z0-9+/]+={0,2})', authHeader)
        if match:
            return match.group(1)

        LOG.error('No NTLM challenge returned from server, '
                  'WWW-Authenticate header: %s' % authHeader)
        raise RuntimeError('Server did not return an NTLM challenge. '
                           'WWW-Authenticate header: %s' % authHeader)

    def __call__(self, request):
        # Attach the NTLM auth handler to the request via response hook
        request.headers['Connection'] = 'Keep-Alive'
        request.register_hook('response', self._handleResponse)
        return request

    def _handleResponse(self, response, **kwargs):
        # Drive the NTLM challenge-response handshake when the server
        # returns 401 with WWW-Authenticate containing NTLM or Negotiate
        if response.status_code != 401:
            return response

        authHeader = response.headers.get('WWW-Authenticate', '')
        if 'NTLM' not in authHeader and 'Negotiate' not in authHeader:
            return response

        LOG.debug('HTTP 401 received with NTLM challenge, starting authentication handshake')

    
        # reused (critical for keep-alive NTLM handshakes)
        response.content
        response.close()

        negotiateMsg = self._buildNegotiateMessage()
        negotiateBase64 = base64.b64encode(negotiateMsg).decode('ascii')

        requestType1 = response.request.copy()
        requestType1.headers['Authorization'] = 'NTLM %s' % negotiateBase64

        adapter = response.connection
        type2Response = adapter.send(requestType1, **kwargs)

        # Step 2: Parse Type 2 (Challenge) and send Type 3 (Auth)
        type2Response.content
        type2Response.close()

        challengeBase64 = self._extractChallengeFromHeader(type2Response)
        authMsg = self._buildAuthenticateMessage(challengeBase64)
        authBase64 = base64.b64encode(authMsg).decode('ascii')

        requestType3 = type2Response.request.copy()
        requestType3.headers['Authorization'] = 'NTLM %s' % authBase64

        finalResponse = adapter.send(requestType3, **kwargs)

        # Carry over history so callers can inspect the handshake
        finalResponse.history = [response, type2Response]
        finalResponse.request = requestType3

        LOG.debug('NTLM handshake complete, status code: %d' % finalResponse.status_code)

        return finalResponse


def passwordAuth(identity, password, **kwargs):
    # password-based HTTP NTLM auth
    return ImpacketHttpNtlmAuth(identity, password=password, **kwargs)


def pthAuth(identity, ntHash, **kwargs):
    #used for pass the hash over http
    hashes = 'aad3b435b51404eeaad3b435b51404ee:%s' % ntHash
    return ImpacketHttpNtlmAuth(identity, hashes=hashes, **kwargs)
