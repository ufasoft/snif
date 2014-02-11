//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_SYSTEM                  0x0
#define FACILITY_STUBS                   0x3
#define FACILITY_IO_ERROR_CODE           0x4


//
// Define the severity codes
//
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: E_Sniffer_BEGIN
//
// MessageText:
//
// Sniffer Begin Error
//
#define E_Sniffer_BEGIN                  ((DWORD)0x8818ABE0L)

//
// MessageId: E_Sniffer_PPPCompression
//
// MessageText:
//
// Sniffer must be run before establishing PPP-connection, because it can not retrive compression history
//
#define E_Sniffer_PPPCompression         ((DWORD)0x8818ABE1L)

//
// MessageId: E_Sniffer_Reboot
//
// MessageText:
//
// You need reboot
//
#define E_Sniffer_Reboot                 ((DWORD)0x8818ABE2L)

//
// MessageId: E_Sniffer_BadPacketFormat
//
// MessageText:
//
// Bad packet format
//
#define E_Sniffer_BadPacketFormat        ((DWORD)0x8818ABE3L)

//
// MessageId: E_Sniffer_UnsupportedNetMonVersion
//
// MessageText:
//
// This version of NetMon unsupported
//
#define E_Sniffer_UnsupportedNetMonVersion ((DWORD)0x8818ABE4L)

//
// MessageId: E_Sniffer_InvalidPPPFormat
//
// MessageText:
//
// Invalid format of PPP frame
//
#define E_Sniffer_InvalidPPPFormat       ((DWORD)0x8818ABE5L)

//
// MessageId: E_Sniffer_WPCap
//
// MessageText:
//
// WPCap error
//
#define E_Sniffer_WPCap                  ((DWORD)0x8818ABE6L)

//
// MessageId: E_Sniffer_SnapLen
//
// MessageText:
//
// Truncated packet. Use: tcpdump -s 0
//
#define E_Sniffer_SnapLen                ((DWORD)0x8818ABE7L)

//
// MessageId: E_Sniffer_BadChecksum
//
// MessageText:
//
// Bad Checksum
//
#define E_Sniffer_BadChecksum            ((DWORD)0x8818ABE8L)

//
// MessageId: E_Sniffer_NoSuchAdapter
//
// MessageText:
//
// No Such Adapter
//
#define E_Sniffer_NoSuchAdapter          ((DWORD)0x8818ABE9L)

//
// MessageId: E_Sniffer_InvalidRpcapURI
//
// MessageText:
//
// Invalid RPCAP URI
//
#define E_Sniffer_InvalidRpcapURI        ((DWORD)0x8818ABEAL)

//
// MessageId: E_Sniffer_InvalidStructSize
//
// MessageText:
//
// Invalid Struct Size
//
#define E_Sniffer_InvalidStructSize      ((DWORD)0x8818ABEBL)

//
// MessageId: E_Sniffer_AdapterNotBinded
//
// MessageText:
//
// Adapter Not Binded
//
#define E_Sniffer_AdapterNotBinded       ((DWORD)0x8818ABECL)

//
// MessageId: E_Sniffer_LoopInOtherThread
//
// MessageText:
//
// Sniffer Loop In Other Thread
//
#define E_Sniffer_LoopInOtherThread      ((DWORD)0x8818ABEDL)

//
// MessageId: E_Sniffer_InvalidWepKey
//
// MessageText:
//
// Invalid WEP key string. Should be 10 or 27 hex-digits
//
#define E_Sniffer_InvalidWepKey          ((DWORD)0x8818ABEEL)

//
// MessageId: E_Sniffer_Wifi_Unknown_Hardware
//
// MessageText:
//
// Unknown Wi-Fi Hardware
//
#define E_Sniffer_Wifi_Unknown_Hardware  ((DWORD)0x8818ABEFL)

//
// MessageId: E_Sniffer_END
//
// MessageText:
//
// Sniffer End Error
//
#define E_Sniffer_END                    ((DWORD)0x8818ABF0L)

