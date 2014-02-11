#pragma once

#ifndef GUID_DEFINED
#	define GUID_DEFINED
typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[ 8 ];
} GUID;
#endif

#ifndef EXTERN_C
#	ifdef __cplusplus
#		define EXTERN_C    extern "C"
#	else
#		define EXTERN_C    extern
#	endif
#endif

#ifdef DEFINE_GUID
#	undef DEFINE_GUID
#endif

#ifdef INITGUID
#	define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
        EXTERN_C const GUID name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }
#else
#	define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    EXTERN_C const GUID name
#endif // INITGUID

