from struct import pack, unpack

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.structure import Structure
from impacket.spnego import GSSAPI, ASN1_SEQUENCE, ASN1_OCTET_STRING, asn1decode, asn1encode

TDPU_CONNECTION_REQUEST = 0xe0
TPDU_CONNECTION_CONFIRM = 0xd0
TDPU_DATA = 0xf0
TPDU_REJECT = 0x50
TPDU_DATA_ACK = 0x60

# RDP_NEG_REQ constants
TYPE_RDP_NEG_REQ = 1
PROTOCOL_RDP = 0
PROTOCOL_SSL = 1
PROTOCOL_HYBRID = 2

# RDP_NEG_RSP constants
TYPE_RDP_NEG_RSP = 2
EXTENDED_CLIENT_DATA_SUPPORTED = 1
DYNVC_GFX_PROTOCOL_SUPPORTED = 2

# RDP_NEG_FAILURE constants
TYPE_RDP_NEG_FAILURE = 3
SSL_REQUIRED_BY_SERVER = 1
SSL_NOT_ALLOWED_BY_SERVER = 2
SSL_CERT_NOT_ON_SERVER = 3
INCONSISTENT_FLAGS = 4
HYBRID_REQUIRED_BY_SERVER = 5
SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 6


class TPKT(Structure):
    commonHdr = (
        ('Version', 'B=3'),
        ('Reserved', 'B=0'),
        ('Length', '>H=len(TPDU)+4'),
        ('_TPDU', '_-TPDU', 'self["Length"]-4'),
        ('TPDU', ':=""'),
    )


class TPDU(Structure):
    commonHdr = (
        ('LengthIndicator', 'B=len(VariablePart)+1'),
        ('Code', 'B=0'),
        ('VariablePart', ':=""'),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data)
        self['VariablePart'] = ''


class CR_TPDU(Structure):
    commonHdr = (
        ('DST-REF', '<H=0'),
        ('SRC-REF', '<H=0'),
        ('CLASS-OPTION', 'B=0'),
        ('Type', 'B=0'),
        ('Flags', 'B=0'),
        ('Length', '<H=8'),
    )


class DATA_TPDU(Structure):
    commonHdr = (
        ('EOT', 'B=0x80'),
        ('UserData', ':=""'),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data)
        self['UserData'] = ''


class RDP_NEG_REQ(CR_TPDU):
    structure = (
        ('requestedProtocols', '<L'),
    )

    def __init__(self, data=None):
        CR_TPDU.__init__(self, data)
        if data is None:
            self['Type'] = TYPE_RDP_NEG_REQ


class RDP_NEG_RSP(CR_TPDU):
    structure = (
        ('selectedProtocols', '<L'),
    )


class RDP_NEG_FAILURE(CR_TPDU):
    structure = (
        ('failureCode', '<L'),
    )


class TSPasswordCreds(GSSAPI):

    def __init__(self, data=None):
        GSSAPI.__init__(self, data)
        del self['UUID']

    def getData(self):
        ans = pack('B', ASN1_SEQUENCE)
        ans += asn1encode(pack('B', 0xa0) +
                          asn1encode(pack('B', ASN1_OCTET_STRING) +
                                     asn1encode(self['domainName'].encode('utf-16le'))) +
                          pack('B', 0xa1) +
                          asn1encode(pack('B', ASN1_OCTET_STRING) +
                                     asn1encode(self['userName'].encode('utf-16le'))) +
                          pack('B', 0xa2) +
                          asn1encode(pack('B', ASN1_OCTET_STRING) +
                                     asn1encode(self['password'].encode('utf-16le'))))
        return ans


class TSCredentials(GSSAPI):

    def __init__(self, data=None):
        GSSAPI.__init__(self, data)
        del self['UUID']

    def getData(self):
        # Let's pack the credentials field
        credentials = pack('B', 0xa1)
        credentials += asn1encode(pack('B', ASN1_OCTET_STRING) +
                                  asn1encode(self['credentials']))

        ans = pack('B', ASN1_SEQUENCE)
        ans += asn1encode(pack('B', 0xa0) +
                          asn1encode(pack('B', 0x02) +
                                     asn1encode(pack('B', self['credType']))) +
                          credentials)
        return ans


class TSRequest(GSSAPI):

    def __init__(self, data=None):
        GSSAPI.__init__(self, data)
        del self['UUID']

    def fromString(self, data=None):
        next_byte = unpack('B', data[:1])[0]
        if next_byte != ASN1_SEQUENCE:
            raise Exception('SEQUENCE expected! (%x)' % next_byte)
        data = data[1:]
        decode_data, total_bytes = asn1decode(data)

        next_byte = unpack('B', decode_data[:1])[0]
        if next_byte != 0xa0:
            raise Exception('0xa0 tag not found %x' % next_byte)
        decode_data = decode_data[1:]
        next_bytes, total_bytes = asn1decode(decode_data)
        # The INTEGER tag must be here
        if unpack('B', next_bytes[0:1])[0] != 0x02:
            raise Exception('INTEGER tag not found %r' % next_byte)
        next_byte, _ = asn1decode(next_bytes[1:])
        self['Version'] = unpack('B', next_byte)[0]
        decode_data = decode_data[total_bytes:]
        next_byte = unpack('B', decode_data[:1])[0]
        if next_byte == 0xa1:
            # We found the negoData token
            decode_data, total_bytes = asn1decode(decode_data[1:])

            next_byte = unpack('B', decode_data[:1])[0]
            if next_byte != ASN1_SEQUENCE:
                raise Exception('ASN1_SEQUENCE tag not found %r' % next_byte)
            decode_data, total_bytes = asn1decode(decode_data[1:])

            next_byte = unpack('B', decode_data[:1])[0]
            if next_byte != ASN1_SEQUENCE:
                raise Exception('ASN1_SEQUENCE tag not found %r' % next_byte)
            decode_data, total_bytes = asn1decode(decode_data[1:])

            next_byte = unpack('B', decode_data[:1])[0]
            if next_byte != 0xa0:
                raise Exception('0xa0 tag not found %r' % next_byte)
            decode_data, total_bytes = asn1decode(decode_data[1:])

            next_byte = unpack('B', decode_data[:1])[0]
            if next_byte != ASN1_OCTET_STRING:
                raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
            decode_data2, total_bytes = asn1decode(decode_data[1:])
            # the rest should be the data
            self['NegoData'] = decode_data2
            decode_data = decode_data[total_bytes + 1:]

        if next_byte == 0xa2:
            # ToDo: Check all this
            # We found the authInfo token
            decode_data, total_bytes = asn1decode(decode_data[1:])
            next_byte = unpack('B', decode_data[:1])[0]
            if next_byte != ASN1_OCTET_STRING:
                raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
            decode_data2, total_bytes = asn1decode(decode_data[1:])
            self['authInfo'] = decode_data2
            decode_data = decode_data[total_bytes + 1:]

        if next_byte == 0xa3:
            # ToDo: Check all this
            # We found the pubKeyAuth token
            decode_data, total_bytes = asn1decode(decode_data[1:])
            next_byte = unpack('B', decode_data[:1])[0]
            if next_byte != ASN1_OCTET_STRING:
                raise Exception('ASN1_OCTET_STRING tag not found %r' % next_byte)
            decode_data2, total_bytes = asn1decode(decode_data[1:])
            self['pubKeyAuth'] = decode_data2

    def getData(self):
        # Do we have pubKeyAuth?
        if 'pubKeyAuth' in self.fields:
            pubKeyAuth = pack('B', 0xa3)
            pubKeyAuth += asn1encode(pack('B', ASN1_OCTET_STRING) +
                                     asn1encode(self['pubKeyAuth']))
        else:
            pubKeyAuth = b''

        if 'authInfo' in self.fields:
            authInfo = pack('B', 0xa2)
            authInfo += asn1encode(pack('B', ASN1_OCTET_STRING) +
                                   asn1encode(self['authInfo']))
        else:
            authInfo = b''

        if 'NegoData' in self.fields:
            negoData = pack('B', 0xa1)
            negoData += asn1encode(pack('B', ASN1_SEQUENCE) +
                                   asn1encode(pack('B', ASN1_SEQUENCE) +
                                              asn1encode(pack('B', 0xa0) +
                                                         asn1encode(pack('B', ASN1_OCTET_STRING) +
                                                                    asn1encode(self['NegoData'])))))
        else:
            negoData = b''
        ans = pack('B', ASN1_SEQUENCE)
        ans += asn1encode(pack('B', 0xa0) +
                          asn1encode(pack('B', 0x02) + asn1encode(pack('B', 0x02))) +
                          negoData + authInfo + pubKeyAuth)

        return ans