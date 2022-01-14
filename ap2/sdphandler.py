from enum import IntFlag, Enum
from ap2.connections.audio import AudioSetup


class SDPHandler():
    # systemcrash 2021
    class SDPAudioFormat(Enum):
        (
            UNSUPPORTED,
            PCM,
            ALAC,
            AAC,
            AAC_ELD,
            OPUS,
        ) = range(6)

    def __init__(self, sdp=''):
        from ap2.connections.audio import AirplayAudFmt

        self.sdp = sdp.splitlines()
        self.has_mfi = False
        self.has_rsa = False
        self.has_fp = False
        self.last_media = ''
        self.has_audio = False
        self.has_video = False
        self.audio_format = self.SDPAudioFormat.UNSUPPORTED
        self.minlatency = 11025
        self.maxlatency = 11025
        self.spf = 0
        for k in self.sdp:
            if 'v=' in k:
                self.ver_line = k
            elif 'o=' in k:
                self.o_line = k
            elif 's=' in k:
                self.subj_line = k
            elif 'c=' in k:
                self.conn_line = k
            elif 't=' in k:
                self.t_line = k
            elif 'm=audio' in k:
                self.has_audio = True
                self.last_media = 'audio'
                self.m_aud_line = k
                start = self.m_aud_line.find('AVP ') + 4
                self.audio_media_type = int(self.m_aud_line[start:])
            elif 'a=rtpmap:' in k and self.last_media == 'audio':
                self.audio_rtpmap = k.split(':')[1]
                start = self.audio_rtpmap.find(':') + 1
                mid = self.audio_rtpmap.find(' ') + 1
                self.payload_type = self.audio_rtpmap[start:mid - 1]  # coerce to int later
                self.audio_encoding = self.audio_rtpmap[mid:]
                if self.audio_encoding == 'AppleLossless':
                    self.audio_format = self.SDPAudioFormat.ALAC
                elif 'mpeg4-generic/' in self.audio_encoding:
                    self.audio_format = self.SDPAudioFormat.AAC
                    discard, self.audio_format_sr, self.audio_format_ch = self.audio_encoding.split('/')
                    self.audio_format_bd = 16
                else:
                    self.audio_format = self.SDPAudioFormat.PCM
                    self.audio_format_bd, self.audio_format_sr, self.audio_format_ch = self.audio_encoding.split('/')
                    self.audio_format_bd = ''.join(filter(str.isdigit, self.audio_format_bd))
            elif 'a=fmtp:' in k and self.payload_type in k:
                self.audio_fmtp = k.split(':')[1]
                self.afp = self.audio_fmtp.split(' ')  # audio format params
                if self.audio_format == self.SDPAudioFormat.ALAC:
                    self.spf = self.afp[1]  # samples per frame
                    # a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100
                    self.params = AudioSetup(
                        codec_tag='alac',
                        ver=0,
                        spf=self.afp[1],
                        compat_ver=self.afp[2],
                        ss=self.afp[3],  # bitdepth
                        hist_mult=self.afp[4],
                        init_hist=self.afp[5],
                        rice_lmt=self.afp[6],
                        cc=self.afp[7],
                        max_run=self.afp[8],
                        mcfs=self.afp[9],
                        abr=self.afp[10],
                        sr=self.afp[11],
                    )
                    self.audio_format_bd = self.afp[3]
                    self.audio_format_ch = self.afp[7]
                    self.audio_format_sr = self.afp[11]
                    self.audio_desc = 'ALAC'
                elif self.audio_format == self.SDPAudioFormat.AAC:
                    self.audio_desc = 'AAC_LC'
                elif self.audio_format == self.SDPAudioFormat.PCM:
                    self.audio_desc = 'PCM'
                elif self.audio_format == self.SDPAudioFormat.OPUS:
                    self.audio_desc = 'OPUS'
                if 'mode=' in self.audio_fmtp:
                    self.audio_format = self.SDPAudioFormat.AAC_ELD
                    for x in self.afp:
                        if 'constantDuration=' in x:
                            start = x.find('constantDuration=') + len('constantDuration=')
                            self.constantDuration = int(x[start:].rstrip(';'))
                            self.spf = self.constantDuration
                        elif 'mode=' in x:
                            start = x.find('mode=') + len('mode=')
                            self.aac_mode = x[start:].rstrip(';')
                    self.audio_desc = 'AAC_ELD'
                for f in AirplayAudFmt:
                    if(self.audio_desc in f.name
                        and self.audio_format_bd in f.name
                        and self.audio_format_sr in f.name
                        and self.audio_format_ch in f.name
                       ):
                        self.AirplayAudFmt = f.value
                        self.audio_format_bd = int(self.audio_format_bd)
                        self.audio_format_ch = int(self.audio_format_ch)
                        self.audio_format_sr = int(self.audio_format_sr)
                        break
                # video fmtp not needed, it seems.
            elif 'a=mfiaeskey:' in k:
                self.has_mfi = True
                self.aeskey = k.split(':')[1]
            elif 'a=rsaaeskey:' in k:
                self.has_rsa = True
                # RSA - Use FeatureFlags.getFeature12(FeatureFlags)
                self.aeskey = k.split(':')[1]
            elif 'a=fpaeskey:' in k:
                self.has_fp = True
                # FairPlay AES key
                self.aeskey = k.split(':')[1]
            elif 'a=aesiv:' in k:
                self.aesiv = k.split(':')[1]
            elif 'a=min-latency:' in k:
                self.minlatency = k.split(':')[1]
            elif 'a=max-latency:' in k:
                self.maxlatency = k.split(':')[1]
            elif 'm=video' in k:
                self.has_video = True
                self.last_media = 'video'
                self.m_video_line = k
                start = self.m_video_line.find('AVP ') + 4
                self.video_media_type = int(self.m_video_line[start:])
            elif 'a=rtpmap:' in k and self.last_media == 'video':
                self.video_rtpmap = k.split(':')[1]
                start = self.video_rtpmap.find(':') + 1
                mid = self.video_rtpmap.find(' ') + 1
                self.video_payload = int(self.video_rtpmap[start:mid - 1])
                self.video_encoding = self.video_rtpmap[mid:]
