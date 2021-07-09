"""
# DXXP parser in Python
# - systemcrash 2021
# License: GPLv2

Behaviour here is derived from that observed within AirPlay v2.
"""

import enum
# from ctypes import *


UnregisteredError = 'Unregistered code type:'


class PlayState(enum.Enum):
    def __str__(self):
        return self.name
    Undefined   = 0
    Playing     = 1
    Paused      = 2
    Stopped     = 3
    FastForward = 4
    Rewind      = 5


class SongType(enum.Enum):
    def __str__(self):
        return self.name
    LocalFile    = 0
    RemoteStream = 1


class Rating(enum.Enum):
    def __str__(self):
        return self.name
    NoRestrictions = 0
    SomeAdvisory   = 1
    CleanLyrics    = 2


class Type(enum.Enum):
    """
    Returns the content type
    """
    def __str__(self):
        return self.name
    Undefined   = 0
    Boolean     = 1  # 1 = true, 0/nothing = false
    UInt8       = 1  # Boolean/UInt8 are the same
    SInt8       = 2
    UInt16      = 3
    SInt16      = 4
    UInt32      = 5
    SInt32      = 6
    UInt64      = 7
    SInt64      = 8
    UTF8Chars   = 9
    Date        = 10  # UNIX UTC: sec since Jan 1970
    Version     = 11  # major -> ms = 16, minor -> ls = 16
    ArrayHeader = 12
    DictHeader  = 13
    Float32     = 14
    Custom      = 15


class Code(enum.Enum):
    """ coerce to string """
    def __str__(self):
        return self.value['inst']
    """ coerce to hex """
    def __hex__(self):
        return self.value['octal']
    """ Codes; octal for reference
    # Other DXXP efforts list other Codes. Add as needed, using the below structure.
    """
    asal = {'octal': 0x6173616C, 'inst': 'daap.songalbum', 'type': Type.UTF8Chars}
    asar = {'octal': 0x61736172, 'inst': 'daap.songartist', 'type': Type.UTF8Chars}
    ascp = {'octal': 0x61736370, 'inst': 'daap.songcomposer', 'type': Type.UTF8Chars}
    ascr = {'octal': 0x61736372, 'inst': 'daap.songcontentrating', 'type': Type.UInt8}
    asdk = {'octal': 0x6173646B, 'inst': 'daap.songdatakind', 'type': Type.UInt8}
    asdc = {'octal': 0x61736463, 'inst': 'daap.songdisccount', 'type': Type.UInt16}
    asdn = {'octal': 0x6173646E, 'inst': 'daap.songdiscnumber', 'type': Type.UInt16}
    asgn = {'octal': 0x6173676E, 'inst': 'daap.songgenre', 'type': Type.UTF8Chars}
    astm = {'octal': 0x6173746D, 'inst': 'daap.songtime', 'type': Type.UInt32}
    astc = {'octal': 0x61737463, 'inst': 'daap.songtrackcount', 'type': Type.UInt16}
    astn = {'octal': 0x6173746E, 'inst': 'daap.songtracknumber', 'type': Type.UInt16}
    caps = {'octal': 0x63617073, 'inst': 'dacp.playerstate', 'type': Type.UInt8}
    mcna = {'octal': 0x6D636E61, 'inst': 'dmap.contentcodesname', 'type': Type.UTF8Chars}
    mcnm = {'octal': 0x6D636E6D, 'inst': 'dmap.contentcodesnumber', 'type': Type.UInt32}
    mcty = {'octal': 0x6D637479, 'inst': 'dmap.contentcodestype', 'type': Type.UInt16}
    mdcl = {'octal': 0x6D64636C, 'inst': 'dmap.dictionary', 'type': Type.DictHeader}
    miid = {'octal': 0x6D696964, 'inst': 'dmap.itemid', 'type': Type.UInt32}
    minm = {'octal': 0x6D696E6D, 'inst': 'dmap.itemname', 'type': Type.UTF8Chars}
    mlit = {'octal': 0x6D6C6974, 'inst': 'dmap.listingitem', 'type': Type.DictHeader}
    mper = {'octal': 0x6D706572, 'inst': 'dmap.persistentid', 'type': Type.UInt64}
    msrv = {'octal': 0x6D737276, 'inst': 'dmap.serverinforesponse', 'type': Type.DictHeader}
    mstt = {'octal': 0x6D737474, 'inst': 'dmap.status', 'type': Type.UInt32}
    msts = {'octal': 0x6D737473, 'inst': 'dmap.statusstring', 'type': Type.UTF8Chars}
    aeSI = {'octal': 0x61655349, 'inst': 'com.apple.itunes.itms-songid', 'type': Type.UInt32}


def parse_dxxp(chunk):
    # Code: 4 bytes
    # Length: 4 bytes
    # Data: (`Length` bytes)
    # Remaining data is to be parsed recursively

    def get_int(data):
        # Return integers of even amount of bytes, or 1 byte
        # Otherwise return 0
        return int.from_bytes(data, byteorder='big') if (len(data) % 2) == 0 or len(data) == 1 else 0

    if(len(chunk) > 0):
        # Define get frame
        def get_next_frame(_in):
            if(len(_in) == 0):
                """
                return when we reached the last frame.
                 Note: if we get a huge amount of frames, one may need
                 to sys.setrecursionlimit(sys.getrecursionlimit()+1) here, but
                 the tradeoff is larger stack size.
                """
                return
            # trigger KeyError if we dont know the Code type:
            code, _typ = '', ''
            try:
                # start 0, end 4
                code = Code.__getitem__(_in[0:4].decode())
                # print('code:', code)
                _typ = code.value['type']
                # print('_typ:', _typ)
            except (KeyError, AttributeError):
                # start 0, end 4
                print(UnregisteredError, _in[0:4].decode())
                pass
            finally:
                pass

            # start 4, end 8
            leng = get_int(_in[4:8])
            # print('tail:', tail)
            # start 8, end 8 + leng
            data = _in[8:8 + leng]
            # print('data:', data)

            if(leng == 0):
                # skip it
                pass
            elif(leng == 0 and _typ  == (Type.Boolean)):
                # In case Boolean has length 0
                print(code, ':', False)
            if(leng > 0):
                # print('fr_length:', leng)
                # print('fr_data:', data)
                if(code == (Code.mlit or Code.msrv or Code.mdcl)):
                    get_next_frame(data)

                elif(code == Code.caps):
                    print(code, ':', PlayState(get_int(data)))

                elif(code == Code.ascr):
                    print(code, ':', Rating(get_int(data)))

                elif(_typ == (Type.Boolean)):
                    print(code, ':', bool(get_int(data)))

                elif(_typ == (Type.UInt8 or Type.UInt16 or Type.UInt32)):
                    print(code, ':', get_int(data))

                elif(_typ == (Type.SInt8 or Type.SInt16 or Type.SInt32)):
                    print(code, ':', get_int(data))

                elif(_typ == (Type.UInt64 or Type.SInt64)):
                    print(code,
                          ':',
                          get_int(data[0:leng]),
                          '/',
                          f'0x{get_int(data[0:leng]):016x}')

                elif(_typ == Type.UTF8Chars):
                    # Just .decode() is OK
                    print(code, ':', data.decode('utf-8'))

                elif(_typ == Type.Date):
                    # Parse a date into UTC, if necessary
                    print(code, ':', get_int(data))

                elif(_typ == Type.Version):
                    print(code, ':', f'{get_int(data[0:2])}.{get_int(data[2:4])}')

                elif(_typ == Type.Float32):
                    pass

                elif(_typ == Type.Custom):
                    pass

            # get subsequent frame (recursive)
            # start 8 + leng
            get_next_frame(_in[8 + leng:])

        # Commence parsing
        get_next_frame(chunk)

        # empty line delineate output.
        print()
