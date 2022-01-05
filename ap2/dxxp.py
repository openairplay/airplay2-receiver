"""
# DXXP parser in Python
# - systemcrash 2021
# License: GPLv2

Behaviour here is derived from that observed within AirPlay v2.
"""

import enum
from datetime import datetime


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
        return self.value['hex']
    """ Codes; hex for reference
    # Other DXXP efforts list other Codes. Add as needed, using the below structure.
    """
    # Values that iOS and Music on macOS send:
    asal = {'hex': 0x6173616C, 'inst': 'daap.songalbum', 'type': Type.UTF8Chars}
    asar = {'hex': 0x61736172, 'inst': 'daap.songartist', 'type': Type.UTF8Chars}
    ascp = {'hex': 0x61736370, 'inst': 'daap.songcomposer', 'type': Type.UTF8Chars}
    ascr = {'hex': 0x61736372, 'inst': 'daap.songcontentrating', 'type': Type.UInt8}
    asdk = {'hex': 0x6173646B, 'inst': 'daap.songdatakind', 'type': Type.UInt8}
    asdc = {'hex': 0x61736463, 'inst': 'daap.songdisccount', 'type': Type.UInt16}
    asdn = {'hex': 0x6173646E, 'inst': 'daap.songdiscnumber', 'type': Type.UInt16}
    asgn = {'hex': 0x6173676E, 'inst': 'daap.songgenre', 'type': Type.UTF8Chars}
    astm = {'hex': 0x6173746D, 'inst': 'daap.songtime', 'type': Type.UInt32}
    astc = {'hex': 0x61737463, 'inst': 'daap.songtrackcount', 'type': Type.UInt16}
    astn = {'hex': 0x6173746E, 'inst': 'daap.songtracknumber', 'type': Type.UInt16}
    caps = {'hex': 0x63617073, 'inst': 'dacp.playerstate', 'type': Type.UInt8}
    mcna = {'hex': 0x6D636E61, 'inst': 'dmap.contentcodesname', 'type': Type.UTF8Chars}
    mcnm = {'hex': 0x6D636E6D, 'inst': 'dmap.contentcodesnumber', 'type': Type.UInt32}
    mcty = {'hex': 0x6D637479, 'inst': 'dmap.contentcodestype', 'type': Type.UInt16}
    mdcl = {'hex': 0x6D64636C, 'inst': 'dmap.dictionary', 'type': Type.DictHeader}
    miid = {'hex': 0x6D696964, 'inst': 'dmap.itemid', 'type': Type.UInt32}
    minm = {'hex': 0x6D696E6D, 'inst': 'dmap.itemname', 'type': Type.UTF8Chars}
    mlit = {'hex': 0x6D6C6974, 'inst': 'dmap.listingitem', 'type': Type.DictHeader}
    mper = {'hex': 0x6D706572, 'inst': 'dmap.persistentid', 'type': Type.UInt64}
    msrv = {'hex': 0x6D737276, 'inst': 'dmap.serverinforesponse', 'type': Type.DictHeader}
    mstt = {'hex': 0x6D737474, 'inst': 'dmap.status', 'type': Type.UInt32}
    msts = {'hex': 0x6D737473, 'inst': 'dmap.statusstring', 'type': Type.UTF8Chars}
    aeSI = {'hex': 0x61655349, 'inst': 'com.apple.itunes.itms-songid', 'type': Type.UInt32}
    # Values that iTunes (for Windows 12.10.10.2) sends (sorted) for music:
    aeCR = {'hex': 0x61654352, 'inst': 'com.apple.itunes.content-rating', 'type': Type.UTF8Chars}
    aeCS = {'hex': 0x61654353, 'inst': 'com.apple.itunes.artworkchecksum', 'type': Type.UInt32}
    aeDL = {'hex': 0x6165444C, 'inst': 'com.apple.itunes.drm-downloader-user-id', 'type': Type.UInt64}
    aeDP = {'hex': 0x61654450, 'inst': 'com.apple.itunes.drm-platform-id', 'type': Type.UInt32}
    aeDR = {'hex': 0x61654452, 'inst': 'com.apple.itunes.drm-user-id', 'type': Type.UInt64}
    aeDV = {'hex': 0x61654456, 'inst': 'com.apple.itunes.drm-versions', 'type': Type.UInt32}
    aeEN = {'hex': 0x6165454E, 'inst': 'daap.songgrouping', 'type': Type.UTF8Chars}
    aeES = {'hex': 0x61654553, 'inst': 'com.apple.itunes.episode-sort', 'type': Type.UInt32}
    aeFA = {'hex': 0x61654641, 'inst': 'com.apple.itunes.drm-family-id', 'type': Type.UInt64}
    aeGD = {'hex': 0x61654744, 'inst': 'com.apple.itunes.gapless-enc-dr', 'type': Type.UInt32}
    aeGE = {'hex': 0x61654745, 'inst': 'com.apple.itunes.gapless-enc-del', 'type': Type.UInt32}
    aeGH = {'hex': 0x61654748, 'inst': 'com.apple.itunes.gapless-heur', 'type': Type.UInt32}
    aeGR = {'hex': 0x61654752, 'inst': 'com.apple.itunes.gapless-resy', 'type': Type.UInt64}
    aeGs = {'hex': 0x61654773, 'inst': 'com.apple.itunes.can-be-genius-seed', 'type': Type.Boolean}
    aeGU = {'hex': 0x61654755, 'inst': 'com.apple.itunes.gapless-dur', 'type': Type.UInt64}
    aeHV = {'hex': 0x61654856, 'inst': 'com.apple.itunes.has-video', 'type': Type.Boolean}
    # 🤮
    aeK1 = {'hex': 0x61654B31, 'inst': 'com.apple.itunes.drm-key1-id', 'type': Type.UInt64}
    aeK2 = {'hex': 0x61654B32, 'inst': 'com.apple.itunes.drm-key2-id', 'type': Type.UInt64}
    aels = {'hex': 0x61656C73, 'inst': 'com.apple.itunes.liked-state', 'type': Type.UInt8}
    aeMK = {'hex': 0x61654D4B, 'inst': 'com.apple.itunes.mediakind', 'type': Type.UInt8}
    aeMk = {'hex': 0x61654D6B, 'inst': 'com.apple.itunes.extended-media-kind', 'type': Type.UInt32}
    aeMX = {'hex': 0x61654D58, 'inst': 'com.apple.itunes.movie-info-xml', 'type': Type.UTF8Chars}
    aeND = {'hex': 0x61654E44, 'inst': 'com.apple.itunes.non-drm-user-id', 'type': Type.UInt64}
    aeNV = {'hex': 0x61654E56, 'inst': 'com.apple.itunes.norm-volume', 'type': Type.UInt32}
    aePC = {'hex': 0x61655043, 'inst': 'com.apple.itunes.is-podcast', 'type': Type.Boolean}
    aeSE = {'hex': 0x61655345, 'inst': 'com.apple.itunes.store-pers-id', 'type': Type.UInt64}
    aeSN = {'hex': 0x6165534E, 'inst': 'daap.songgrouping', 'type': Type.UTF8Chars}
    aeSU = {'hex': 0x61655355, 'inst': 'com.apple.itunes.season-num', 'type': Type.UInt32}
    aeXD = {'hex': 0x61655844, 'inst': 'com.apple.itunes.xid', 'type': Type.UTF8Chars}
    agrp = {'hex': 0x61677270, 'inst': 'daap.songgrouping', 'type': Type.UTF8Chars}
    ajAE = {'hex': 0x616A4145, 'inst': 'com.apple.itunes.store.ams-episode-type', 'type': Type.UInt8}
    ajal = {'hex': 0x616A616C, 'inst': 'com.apple.itunes.store.album-liked-state', 'type': Type.Boolean}
    ajAS = {'hex': 0x616A4153, 'inst': 'com.apple.itunes.store.ams-episode-sort-order', 'type': Type.UInt8}
    ajAT = {'hex': 0x616A4154, 'inst': 'com.apple.itunes.store.ams-show-type', 'type': Type.UInt8}
    ajAV = {'hex': 0x616A4156, 'inst': 'com.apple.itunes.store.is-ams-video', 'type': Type.Boolean}
    ajcA = {'hex': 0x616A6341, 'inst': 'com.apple.itunes.store.show-composer-as-artist', 'type': Type.Boolean}
    ajuw = {'hex': 0x616A7577, 'inst': 'com.apple.itunes.store.use-work-name-as-display-name', 'type': Type.Boolean}
    amvc = {'hex': 0x616D7663, 'inst': 'daap.songmovementcount', 'type': Type.UInt16}
    amvm = {'hex': 0x616D766D, 'inst': 'daap.songmovementname', 'type': Type.UTF8Chars}
    amvn = {'hex': 0x616D766E, 'inst': 'daap.songmovementnumber', 'type': Type.UInt16}
    asaa = {'hex': 0x61736161, 'inst': 'daap.songalbumartist', 'type': Type.UTF8Chars}
    asac = {'hex': 0x61736163, 'inst': 'daap.songartworkcount', 'type': Type.UInt16}
    asai = {'hex': 0x61736169, 'inst': 'daap.songalbumid', 'type': Type.UInt64}
    asas = {'hex': 0x61736173, 'inst': 'daap.songalbumuserratingstatus', 'type': Type.UInt8}
    asbk = {'hex': 0x6173626B, 'inst': 'daap.bookmarkable', 'type': Type.Boolean}
    asbr = {'hex': 0x61736272, 'inst': 'daap.songbitrate', 'type': Type.UInt16}
    asbt = {'hex': 0x61736274, 'inst': 'daap.songbeatsperminute', 'type': Type.UInt16}
    ascd = {'hex': 0x61736364, 'inst': 'daap.songcodectype', 'type': Type.UInt32}
    ascm = {'hex': 0x6173636d, 'inst': 'daap.songcomment', 'type': Type.UTF8Chars}
    ascn = {'hex': 0x6173636E, 'inst': 'daap.songgrouping', 'type': Type.UTF8Chars}
    asco = {'hex': 0x6173636f, 'inst': 'daap.songcompilation', 'type': Type.UInt8}
    ascs = {'hex': 0x61736373, 'inst': 'daap.songcodecsubtype', 'type': Type.UInt32}
    asct = {'hex': 0x61736374, 'inst': 'daap.songgrouping', 'type': Type.UTF8Chars}
    asda = {'hex': 0x61736461, 'inst': 'daap.songdateadded', 'type': Type.Date}
    asdb = {'hex': 0x61736462, 'inst': 'daap.songdisabled', 'type': Type.Boolean}
    asdm = {'hex': 0x6173646d, 'inst': 'daap.songdatemodified', 'type': Type.Date}
    asdt = {'hex': 0x61736474, 'inst': 'daap.songdescription', 'type': Type.UInt8}
    ased = {'hex': 0x61736564, 'inst': 'daap.songextradata', 'type': Type.UInt16}
    aseq = {'hex': 0x61736571, 'inst': 'daap.songeqpreset', 'type': Type.UTF8Chars}
    ases = {'hex': 0x61736573, 'inst': 'daap.songexcludefromshuffle', 'type': Type.Boolean}
    asfm = {'hex': 0x6173666D, 'inst': 'daap.songformat', 'type': Type.UTF8Chars}
    asgp = {'hex': 0x61736770, 'inst': 'daap.songgapless', 'type': Type.Boolean}
    ashp = {'hex': 0x61736870, 'inst': 'daap.songhasbeenplayed', 'type': Type.Boolean}
    askd = {'hex': 0x61736B64, 'inst': 'daap.songlastskipdate', 'type': Type.Date}
    askp = {'hex': 0x61736B70, 'inst': 'daap.songuserskipcount', 'type': Type.UInt32}
    aslr = {'hex': 0x61736C72, 'inst': 'daap.songalbumuserrating', 'type': Type.UInt8}
    asls = {'hex': 0x61736C73, 'inst': 'daap.songlongsize', 'type': Type.UInt64}
    aspc = {'hex': 0x61737063, 'inst': 'daap.songuserplaycount', 'type': Type.UInt32}
    aspl = {'hex': 0x6173706c, 'inst': 'daap.songdateplayed', 'type': Type.Date}
    aspu = {'hex': 0x61737075, 'inst': 'daap.songpodcasturl', 'type': Type.UTF8Chars}
    asri = {'hex': 0x61737269, 'inst': 'daap.songartistid', 'type': Type.UInt64}
    asrs = {'hex': 0x61737273, 'inst': 'daap.songuserratingstatus', 'type': Type.UInt8}
    asrv = {'hex': 0x61737276, 'inst': 'daap.songrelativevolume', 'type': Type.UInt8}
    assa = {'hex': 0x61737361, 'inst': 'daap.sortartist', 'type': Type.UTF8Chars}
    assc = {'hex': 0x61737363, 'inst': 'daap.sortcomposer', 'type': Type.UTF8Chars}
    assl = {'hex': 0x6173736C, 'inst': 'daap.sortalbumartist', 'type': Type.UTF8Chars}
    assn = {'hex': 0x6173736E, 'inst': 'daap.sortname', 'type': Type.UTF8Chars}
    assp = {'hex': 0x61737370, 'inst': 'daap.songstoptime', 'type': Type.UInt32}
    assr = {'hex': 0x61737372, 'inst': 'daap.songsamplerate', 'type': Type.UInt32}
    asss = {'hex': 0x61737373, 'inst': 'daap.sortseriesname', 'type': Type.UTF8Chars}
    asst = {'hex': 0x61737374, 'inst': 'daap.songstarttime', 'type': Type.UInt32}
    assu = {'hex': 0x61737375, 'inst': 'daap.sortalbum', 'type': Type.UTF8Chars}
    assz = {'hex': 0x6173737A, 'inst': 'daap.songsize', 'type': Type.UInt32}
    asur = {'hex': 0x61737572, 'inst': 'daap.songuserrating', 'type': Type.UInt8}
    asyr = {'hex': 0x61737972, 'inst': 'daap.songyear', 'type': Type.UInt16}
    awrk = {'hex': 0x6177726B, 'inst': 'daap.songwork', 'type': Type.UTF8Chars}
    mdst = {'hex': 0x6D647374, 'inst': 'dmap.downloadstatus', 'type': Type.UInt8}
    meia = {'hex': 0x6d656961, 'inst': 'dmap.itemdateadded', 'type': Type.Date}
    meip = {'hex': 0x6d656970, 'inst': 'dmap.itemdateplayed', 'type': Type.Date}
    mext = {'hex': 0x6D657874, 'inst': 'dmap.objectextradata', 'type': Type.UInt16}
    mikd = {'hex': 0x6D696B64, 'inst': 'dmap.itemkind', 'type': Type.UInt8}


def parse_dxxp(chunk):
    # Code: 4 bytes
    # Length: 4 bytes
    # Data: ({Length} bytes)
    # Remaining data is to be parsed recursively

    def get_int(data):
        # Return integers from bytes
        return int.from_bytes(data, byteorder='big')

    if(len(chunk) > 0):
        # Define get frame
        def get_next_frame(_in, buffer, rec=0):
            rec += 1
            # print(rec)
            if(len(_in) == 0):
                """
                return when we reached the last frame.
                 Note: if we get a huge amount of frames, one may need
                 to sys.setrecursionlimit(sys.getrecursionlimit()+1) here, but
                 the tradeoff is larger stack size.
                """
                return buffer
            # trigger KeyError if we dont know the Code type:
            code, _typ = '', ''
            # start 4, end 8
            leng = get_int(_in[4:8])
            try:
                # start 0, end 4
                code = Code.__getitem__(_in[0:4].decode())
                # print('code:', code)
                _typ = code.value['type']
                # print('_typ:', _typ)
            except (KeyError, AttributeError):
                # If the tag has some data, may be interesting.
                if leng > 0:
                    # start 0, end 4
                    print(UnregisteredError, _in[0:4].decode(), "; length:", leng)
                pass
            finally:
                pass

            # start 8, end 8 + leng
            data = _in[8:8 + leng]
            # print('data:', data)
            # print('leng:', leng)

            if(leng == 0 and _typ  == (Type.Boolean)):
                # In case Boolean has length 0
                buffer += f'{code}: {False}'
            elif(leng == 0):
                # skip it
                buffer += ''
            # Non-zero data usually interesting. Tiring to examine lots of default (0) values.
            # iTunes sends ~100 values, wherein usually about ~25 are set to anything meaningful.
            # This elif clause will also ignore Booleans set to False (0).
            elif(leng > 0 and get_int(data) != 0):
                # print('fr_length:', leng)
                # print('fr_data:', data)
                if(code == (Code.mlit or Code.msrv or Code.mdcl)):
                    value = get_next_frame(data, buffer, rec)
                    if value is not None:
                        return value

                elif(code == Code.caps):
                    # print('in1', rec)
                    buffer += f'{code}: {PlayState(get_int(data))}\n'

                elif(code == Code.ascr):
                    # print('in2', rec)
                    buffer += f'{code}: {Rating(get_int(data))}\n'

                elif(_typ == (Type.Boolean)):
                    # print('in3', rec)
                    buffer += f'{code}: {bool(get_int(data))}\n'

                elif(_typ == (Type.UInt8 or Type.UInt16 or Type.UInt32)):
                    # print('in4', rec)
                    buffer += f'{code}: {get_int(data)}\n'

                elif(_typ == (Type.SInt8 or Type.SInt16 or Type.SInt32)):
                    # print('in5', rec)
                    buffer += f'{code}: {get_int(data)}\n'

                elif(_typ == (Type.UInt64 or Type.SInt64)):
                    # print('in6', rec)
                    if 'id' in code.value['inst']:
                        # print('in6a', rec)
                        buffer += f'{code}: 0x{get_int(data[0:leng]):016x}\n'
                    else:
                        # print('in6b', rec)
                        buffer += f'{code}: {get_int(data[0:leng])}\n'
                elif(_typ == Type.UTF8Chars):
                    # Just .decode() is OK
                    # print('in7', rec)
                    buffer += f'{code}: {data.decode("utf-8")}\n'

                elif(_typ == Type.Date):
                    # Parse a date into UTC
                    # print('in8', rec)
                    buffer += f'{code}: {datetime.fromtimestamp(get_int(data))}\n'

                elif(_typ == Type.Version):
                    # print('in9', rec)
                    buffer += f'{code}: {get_int(data[0:2])}.{get_int(data[2:4])}\n'

                elif(_typ == Type.Float32):
                    # print('in10', rec)
                    pass

                elif(_typ == Type.Custom):
                    # print('in11', rec)
                    pass

                else:
                    return buffer

            # get subsequent frame (recursive)
            # start 8 + leng
            value = get_next_frame(_in[8 + leng:], buffer, rec)
            if value is not None:
                return value

        # Commence parsing
        return 'DMAP:\n' + get_next_frame(chunk, '', 0)

    # empty line delineate output.
