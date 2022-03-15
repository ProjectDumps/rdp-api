import socket
import sys
import logging
from binascii import a2b_hex
from Cryptodome.Cipher import ARC4
from impacket import ntlm
from RDPLogic import rdp_logic


try:
    from OpenSSL import SSL, crypto
except:
    logging.critical("pyOpenSSL is not installed, can't continue")
    sys.exit(1)


class SPNEGOCipher:
    def __init__(self, flags, randomSessionKey):
        self.__flags = flags
        if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            self.__clientSigningKey = ntlm.SIGNKEY(self.__flags, randomSessionKey)
            self.__serverSigningKey = ntlm.SIGNKEY(self.__flags, randomSessionKey, "Server")
            self.__clientSealingKey = ntlm.SEALKEY(self.__flags, randomSessionKey)
            self.__serverSealingKey = ntlm.SEALKEY(self.__flags, randomSessionKey, "Server")
            # Preparing the keys handle states
            cipher3 = ARC4.new(self.__clientSealingKey)
            self.__clientSealingHandle = cipher3.encrypt
            cipher4 = ARC4.new(self.__serverSealingKey)
            self.__serverSealingHandle = cipher4.encrypt
        else:
            # Same key for everything
            self.__clientSigningKey = randomSessionKey
            self.__serverSigningKey = randomSessionKey
            self.__clientSealingKey = randomSessionKey
            self.__clientSealingKey = randomSessionKey
            cipher = ARC4.new(self.__clientSigningKey)
            self.__clientSealingHandle = cipher.encrypt
            self.__serverSealingHandle = cipher.encrypt
        self.__sequence = 0

    def encrypt(self, plain_data):
        if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            # When NTLM2 is on, we sign the whole pdu, but encrypt just
            # the data, not the dcerpc header. Weird..
            sealedMessage, signature = ntlm.SEAL(self.__flags,
                                                 self.__clientSigningKey,
                                                 self.__clientSealingKey,
                                                 plain_data,
                                                 plain_data,
                                                 self.__sequence,
                                                 self.__clientSealingHandle)
        else:
            sealedMessage, signature = ntlm.SEAL(self.__flags,
                                                 self.__clientSigningKey,
                                                 self.__clientSealingKey,
                                                 plain_data,
                                                 plain_data,
                                                 self.__sequence,
                                                 self.__clientSealingHandle)
        self.__sequence += 1
        return signature, sealedMessage

    def decrypt(self, answer):
        if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            # TODO: FIX THIS, it's not calculating the signature well
            # Since I'm not testing it we don't care... yet
            answer, signature = ntlm.SEAL(self.__flags,
                                          self.__serverSigningKey,
                                          self.__serverSealingKey,
                                          answer,
                                          answer,
                                          self.__sequence,
                                          self.__serverSealingHandle)
        else:
            answer, signature = ntlm.SEAL(self.__flags,
                                          self.__serverSigningKey,
                                          self.__serverSealingKey,
                                          answer,
                                          answer,
                                          self.__sequence,
                                          self.__serverSealingHandle)
            self.__sequence += 1
        return signature, answer


def check_rdp(host, username, password, port, domain, hashes=None):
    if hashes is not None:
        lmhash, nthash = hashes.split(':')
        lmhash = a2b_hex(lmhash)
        nthash = a2b_hex(nthash)
    else:
        lmhash = ''
        nthash = ''
    tpkt = rdp_logic.TPKT()
    tpdu = rdp_logic.TPDU()
    rdp_neg = rdp_logic.RDP_NEG_REQ()
    rdp_neg['Type'] = rdp_logic.TYPE_RDP_NEG_REQ
    rdp_neg['requestedProtocols'] = rdp_logic.PROTOCOL_HYBRID | rdp_logic.PROTOCOL_SSL
    tpdu['VariablePart'] = rdp_neg.getData()
    tpdu['Code'] = rdp_logic.TDPU_CONNECTION_REQUEST
    tpkt['TPDU'] = tpdu.getData()
    s = socket.socket()
    try:
        s.connect((host, port))
    except:
        return "Access Denied"
    s.sendall(tpkt.getData())
    pkt = s.recv(8192)
    tpkt.fromString(pkt)
    tpdu.fromString(tpkt['TPDU'])
    cr_tpdu = rdp_logic.CR_TPDU(tpdu['VariablePart'])
    if cr_tpdu['Type'] == rdp_logic.TYPE_RDP_NEG_FAILURE:
        rdp_failure = rdp_logic.RDP_NEG_FAILURE(tpdu['VariablePart'])
        rdp_failure.dump()
        logging.error("Server doesn't support PROTOCOL_HYBRID, hence we can't use CredSSP to check credentials")
        return "Server doesn't support PROTOCOL_HYBRID, hence we can't use CredSSP to check credentials"
    else:
        rdp_neg.fromString(tpdu['VariablePart'])
    ctx = SSL.Context(SSL.TLSv1_2_METHOD)
    ctx.set_cipher_list(b'RC4,AES')
    tls = SSL.Connection(ctx, s)
    tls.set_connect_state()
    tls.do_handshake()
    auth = ntlm.getNTLMSSPType1('', '', True, use_ntlmv2=True)
    ts_request = rdp_logic.TSRequest()
    ts_request['NegoData'] = auth.getData()
    tls.send(ts_request.getData())
    buff = tls.recv(4096)
    ts_request.fromString(buff)
    type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, ts_request['NegoData'], username, password, domain,
                                                     lmhash, nthash, use_ntlmv2=True)
    server_cert = tls.get_peer_certificate()
    pkey = server_cert.get_pubkey()
    dump = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pkey)
    dump = dump[7:]
    dump = b'\x30' + rdp_logic.asn1encode(dump)
    cipher = SPNEGOCipher(type3['flags'], exportedSessionKey)
    signature, cripted_key = cipher.encrypt(dump)
    ts_request['NegoData'] = type3.getData()
    ts_request['pubKeyAuth'] = signature.getData() + cripted_key
    try:
        tls.send(ts_request.getData())
        buff = tls.recv(1024)
    except Exception as err:
        if str(err).find("denied") > 0:
            logging.error("Access Denied")
            return "Access Denied"
        else:
            logging.error(err)
            return err
        return "Access Denied"
    ts_request = rdp_logic.TSRequest(buff)
    signature, plain_text = cipher.decrypt(ts_request['pubKeyAuth'][16:])
    tsp = rdp_logic.TSPasswordCreds()
    tsp['domainName'] = domain
    tsp['userName'] = username
    tsp['password'] = password
    tsc = rdp_logic.TSCredentials()
    tsc['credType'] = 1
    tsc['credentials'] = tsp.getData()
    signature, cripted_creds = cipher.encrypt(tsc.getData())
    ts_request = rdp_logic.TSRequest()
    ts_request['authInfo'] = signature.getData() + cripted_creds
    tls.send(ts_request.getData())
    tls.close()
    logging.info("Access Granted")
    return "Access Granted"
