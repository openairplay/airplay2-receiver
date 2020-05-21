#ifndef __APPLE_ALAC_H
#define __APPLE_ALAC_H

#include <stdint.h>

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#if defined(TARGET_OS_WIN32) || defined(_WIN32)
#ifdef LIBALAC_EXPORTS  
#define LIBALAC_API __declspec(dllexport)   
#else  
#define LIBALAC_API __declspec(dllimport)   
#endif  
#else
#define LIBALAC_API
#endif

EXTERNC LIBALAC_API int apple_alac_init(int32_t fmtp[12]);
EXTERNC LIBALAC_API int apple_alac_terminate();
EXTERNC LIBALAC_API int apple_alac_decode_frame(unsigned char *sampleBuffer, uint32_t bufferLength,
                                    unsigned char *dest, int *outsize);

#undef EXTERNC

#endif /* __APPLE_ALAC_H */
