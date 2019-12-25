#include <string.h>

// these are headers for the ALAC decoder, utilities and endian utilities
#include "ALACBitUtilities.h"
#include "ALACDecoder.h"
#include "EndianPortable.h"

#include "apple_alac.h"

typedef struct magicCookie {
  ALACSpecificConfig config;
  ALACAudioChannelLayout channelLayoutInfo; // seems to be unused
} magicCookie;

magicCookie cookie;
ALACDecoder *theDecoder;

extern "C" int apple_alac_init(int32_t fmtp[12]) {

  int res = 0;
  memset(&cookie, 0, sizeof(magicCookie));

  // create a magic cookie for the decoder from the fmtp information. It seems to be in the same
  // format as a simple magic cookie

  cookie.config.frameLength = Swap32NtoB(352);
  cookie.config.compatibleVersion = fmtp[2];         // should be zero, uint8_t
  cookie.config.bitDepth = fmtp[3];                  // uint8_t expected to be 16
  cookie.config.pb = fmtp[4];                        // uint8_t should be 40;
  cookie.config.mb = fmtp[5];                        // uint8_t should be 10;
  cookie.config.kb = fmtp[6];                        // uint8_t should be 14;
  cookie.config.numChannels = fmtp[7];               // uint8_t expected to be 2
  cookie.config.maxRun = Swap16NtoB(fmtp[8]);        // uint16_t expected to be 255
  cookie.config.maxFrameBytes = Swap32NtoB(fmtp[9]); // uint32_t should be 0;
  cookie.config.avgBitRate = Swap32NtoB(fmtp[10]);   // uint32_t should be 0;;
  cookie.config.sampleRate = Swap32NtoB(fmtp[11]);   // uint32_t expected to be 44100;

  theDecoder = new ALACDecoder;
  res = theDecoder->Init(&cookie, sizeof(magicCookie));

  return res;
}

extern "C" int apple_alac_decode_frame(unsigned char *sampleBuffer, uint32_t bufferLength,
                                       unsigned char *dest, int *outsize) {

  uint32_t numFrames = 0;
  int32_t res = 0;
  BitBuffer theInputBuffer;
  BitBufferInit(&theInputBuffer, sampleBuffer, bufferLength);
  res = theDecoder->Decode(&theInputBuffer, dest, Swap32BtoN(cookie.config.frameLength),
                     cookie.config.numChannels, &numFrames);
  *outsize = numFrames;
  return res;
}

extern "C" int apple_alac_terminate() {
  delete (theDecoder);
  return 0;
}
