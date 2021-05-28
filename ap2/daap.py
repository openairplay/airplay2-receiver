# DAAP Format 
# from http://daap.sourceforge.net/docs/index.html
#
# 0-3   Content Code
# 4-7   Length
# 8+    Data
def parse_daap(frame): 
    offset = 8

    print("DAAP FRAME", frame)

    def read_frame():
        nonlocal offset

        length = int(frame[offset]) * 0xffffff + int(frame[offset + 1]) * 0xffff + int(frame[offset + 2]) * 0xff + int(frame[offset + 3])
        offset += length + 8

        return frame[(offset - length - 4) : (offset - 4)]

    def read_text_frame():
        return str(read_frame(), 'UTF-8')

    if frame[0:4] == b'mlit': 
        # skip header
        while frame[offset] != 0:
            offset += 1

        # skip unreadable field
        read_frame()

        # read text fields
        album = read_text_frame()
        artist = [read_text_frame(), read_text_frame()]
        genres = read_text_frame()
        track = read_text_frame()

        print("ALBUM", album)
        print("ARTIST", artist)
        print("GENRES", genres)
        print("TRACK", track)