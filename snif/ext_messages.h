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
// MessageId: 0x80072714L (No symbolic name defined)
//
// MessageText:
//
// Interrupted function call
//


//
// MessageId: 0x8007271DL (No symbolic name defined)
//
// MessageText:
//
// Permission denied
//


//
// MessageId: 0x8007271EL (No symbolic name defined)
//
// MessageText:
//
// Bad address
//


//
// MessageId: 0x80072726L (No symbolic name defined)
//
// MessageText:
//
// Invalid argument
//


//
// MessageId: 0x80072728L (No symbolic name defined)
//
// MessageText:
//
// Too many open files
//


//
// MessageId: 0x80072733L (No symbolic name defined)
//
// MessageText:
//
// Resource temporarily unavailable
//


//
// MessageId: 0x80072734L (No symbolic name defined)
//
// MessageText:
//
// Operation now in progress
//


//
// MessageId: 0x80072735L (No symbolic name defined)
//
// MessageText:
//
// Operation already in progress
//


//
// MessageId: 0x80072736L (No symbolic name defined)
//
// MessageText:
//
// Socket operation on non-socket
//


//
// MessageId: 0x80072737L (No symbolic name defined)
//
// MessageText:
//
// Destination address required
//


//
// MessageId: 0x80072738L (No symbolic name defined)
//
// MessageText:
//
// Message too long
//


//
// MessageId: 0x80072739L (No symbolic name defined)
//
// MessageText:
//
// Protocol wrong type for socket
//


//
// MessageId: 0x8007273AL (No symbolic name defined)
//
// MessageText:
//
// Bad protocol option
//


//
// MessageId: 0x8007273BL (No symbolic name defined)
//
// MessageText:
//
// Protocol not supported
//


//
// MessageId: 0x8007273CL (No symbolic name defined)
//
// MessageText:
//
// Socket type not supported
//


//
// MessageId: 0x8007273DL (No symbolic name defined)
//
// MessageText:
//
// Operation not supported
//


//
// MessageId: 0x8007273EL (No symbolic name defined)
//
// MessageText:
//
// Protocol family not supported
//


//
// MessageId: 0x8007273FL (No symbolic name defined)
//
// MessageText:
//
// Address family not supported by protocol family
//


//
// MessageId: 0x80072740L (No symbolic name defined)
//
// MessageText:
//
// Address already in use
//


//
// MessageId: 0x80072741L (No symbolic name defined)
//
// MessageText:
//
// Cannot assign requested address
//


//
// MessageId: 0x80072742L (No symbolic name defined)
//
// MessageText:
//
// Network is down
//


//
// MessageId: 0x80072743L (No symbolic name defined)
//
// MessageText:
//
// Network is unreachable
//


//
// MessageId: 0x80072744L (No symbolic name defined)
//
// MessageText:
//
// Network dropped connection on reset
//


//
// MessageId: 0x80072745L (No symbolic name defined)
//
// MessageText:
//
// Software caused connection abort
//


//
// MessageId: 0x80072746L (No symbolic name defined)
//
// MessageText:
//
// Connection reset by peer
//


//
// MessageId: 0x80072747L (No symbolic name defined)
//
// MessageText:
//
// No buffer space available
//


//
// MessageId: 0x80072748L (No symbolic name defined)
//
// MessageText:
//
// Socket is already connected
//


//
// MessageId: 0x80072749L (No symbolic name defined)
//
// MessageText:
//
// Socket is not connected
//


//
// MessageId: 0x8007274AL (No symbolic name defined)
//
// MessageText:
//
// Cannot send after socket shutdown
//


//
// MessageId: 0x8007274CL (No symbolic name defined)
//
// MessageText:
//
// Connection timed out
//


//
// MessageId: 0x8007274DL (No symbolic name defined)
//
// MessageText:
//
// Connection refused
//


//
// MessageId: 0x80072750L (No symbolic name defined)
//
// MessageText:
//
// Host is down
//


//
// MessageId: 0x80072751L (No symbolic name defined)
//
// MessageText:
//
// No route to host
//


//
// MessageId: 0x80072753L (No symbolic name defined)
//
// MessageText:
//
// Too many processes
//


//
// MessageId: 0x8007276BL (No symbolic name defined)
//
// MessageText:
//
// Network subsystem is unavailable
//


//
// MessageId: 0x8007276CL (No symbolic name defined)
//
// MessageText:
//
// WS2_32.DLL version out of range
//


//
// MessageId: 0x8007276DL (No symbolic name defined)
//
// MessageText:
//
// Successful WSAStartup not yet performed
//


//
// MessageId: 0x8007276EL (No symbolic name defined)
//
// MessageText:
//
// Graceful shutdown in progress
//


//
// MessageId: 0x8007277DL (No symbolic name defined)
//
// MessageText:
//
// Class type not found
//


//
// MessageId: 0x80072AF9L (No symbolic name defined)
//
// MessageText:
//
// Host not found
//


//
// MessageId: 0x80072AFAL (No symbolic name defined)
//
// MessageText:
//
// Non-authoritative host not found
//


//
// MessageId: 0x80072AFBL (No symbolic name defined)
//
// MessageText:
//
// This is a non-recoverable error
//


//
// MessageId: 0x80072AFCL (No symbolic name defined)
//
// MessageText:
//
// Valid name, no data record of requested type
//


//
// MessageId: E_EXT_BASE
//
// MessageText:
//
// Error in MapFile
//
#define E_EXT_BASE                       ((DWORD)0x880C0000L)

//
// MessageId: E_EXT_MAP
//
// MessageText:
//
// Error in MapFile
//
#define E_EXT_MAP                        ((DWORD)0x880C7531L)

//
// MessageId: E_EXT_EndOfStream
//
// MessageText:
//
// EndOfStream
//
#define E_EXT_EndOfStream                ((DWORD)0x880C7532L)

//
// MessageId: E_EXT_VartypeNotSupported
//
// MessageText:
//
// VarType not supported
//
#define E_EXT_VartypeNotSupported        ((DWORD)0x880C7533L)

//
// MessageId: E_EXT_InvalidDimCount
//
// MessageText:
//
// Invalid dim count
//
#define E_EXT_InvalidDimCount            ((DWORD)0x880C7534L)

//
// MessageId: E_EXT_BlobNotInitialized
//
// MessageText:
//
// Blob not initialized
//
#define E_EXT_BlobNotInitialized         ((DWORD)0x880C7535L)

//
// MessageId: E_EXT_COMPRESS
//
// MessageText:
//
// Compress error
//
#define E_EXT_COMPRESS                   ((DWORD)0x880C7536L)

//
// MessageId: E_EXT_REGISTRY
//
// MessageText:
//
// Registry error
//
#define E_EXT_REGISTRY                   ((DWORD)0x880C7537L)

//
// MessageId: E_EXT_IndexOutOfRange
//
// MessageText:
//
// Index out of range
//
#define E_EXT_IndexOutOfRange            ((DWORD)0x880C7538L)

//
// MessageId: E_EXT_InvalidFlags
//
// MessageText:
//
// Invalid flags
//
#define E_EXT_InvalidFlags               ((DWORD)0x880C7539L)

//
// MessageId: E_EXT_IncorrectVariant
//
// MessageText:
//
// Incorrect variant
//
#define E_EXT_IncorrectVariant           ((DWORD)0x880C753AL)

//
// MessageId: E_EXT_ItemNotFound
//
// MessageText:
//
// Item not found
//
#define E_EXT_ItemNotFound               ((DWORD)0x880C753BL)

//
// MessageId: E_EXT_DCOMnotInstalled
//
// MessageText:
//
// DCOM not installed
//
#define E_EXT_DCOMnotInstalled           ((DWORD)0x880C753CL)

//
// MessageId: E_EXT_VariantMustBeArray
//
// MessageText:
//
// Variant must be array
//
#define E_EXT_VariantMustBeArray         ((DWORD)0x880C753DL)

//
// MessageId: E_EXT_InvalidTypeForThisOperation
//
// MessageText:
//
// Invalid type for this operation
//
#define E_EXT_InvalidTypeForThisOperation ((DWORD)0x880C753EL)

//
// MessageId: E_EXT_QueueOverflow
//
// MessageText:
//
// Overflow of queue
//
#define E_EXT_QueueOverflow              ((DWORD)0x880C753FL)

//
// MessageId: E_EXT_NoMoreServiceHandlers
//
// MessageText:
//
// No more Service handlers
//
#define E_EXT_NoMoreServiceHandlers      ((DWORD)0x880C7540L)

//
// MessageId: E_EXT_AlreadyOpened
//
// MessageText:
//
// Object already Opened
//
#define E_EXT_AlreadyOpened              ((DWORD)0x880C7541L)

//
// MessageId: E_EXT_InvalidRegistrationCode
//
// MessageText:
//
// Invalid Registration Code
//
#define E_EXT_InvalidRegistrationCode    ((DWORD)0x880C7542L)

//
// MessageId: E_EXT_DuplicateName
//
// MessageText:
//
// Duplicate Name
//
#define E_EXT_DuplicateName              ((DWORD)0x880C7543L)

//
// MessageId: E_EXT_InvalidValue
//
// MessageText:
//
// Invalid Value
//
#define E_EXT_InvalidValue               ((DWORD)0x880C7544L)

//
// MessageId: E_EXT_ThreadStopped
//
// MessageText:
//
// Thread Stopped
//
#define E_EXT_ThreadStopped              ((DWORD)0x880C7545L)

//
// MessageId: E_EXT_InvalidFileHeader
//
// MessageText:
//
// Invalid File Header
//
#define E_EXT_InvalidFileHeader          ((DWORD)0x880C7546L)

//
// MessageId: E_EXT_IncompatibleFileVersion
//
// MessageText:
//
// Incompatible File Version
//
#define E_EXT_IncompatibleFileVersion    ((DWORD)0x880C7547L)

//
// MessageId: E_EXT_InvalidSignature
//
// MessageText:
//
// Invalid Signature
//
#define E_EXT_InvalidSignature           ((DWORD)0x880C7548L)

//
// MessageId: E_EXT_UnknownVersionRegcode
//
// MessageText:
//
// Unknown version of Regcode
//
#define E_EXT_UnknownVersionRegcode      ((DWORD)0x880C7549L)

//
// MessageId: E_EXT_InterfaceAlreadyAssigned
//
// MessageText:
//
// Interface already assigned
//
#define E_EXT_InterfaceAlreadyAssigned   ((DWORD)0x880C754AL)

//
// MessageId: E_EXT_InFindHandler
//
// MessageText:
//
// Excheption In FindHandlerForForeignException
//
#define E_EXT_InFindHandler              ((DWORD)0x880C754BL)

//
// MessageId: E_EXT_FindHandler
//
// MessageText:
//
// Excheption In FindHandler
//
#define E_EXT_FindHandler                ((DWORD)0x880C754CL)

//
// MessageId: E_EXT_InvalidExceptionMagicNumber
//
// MessageText:
//
// Invalid Exception Magic number
//
#define E_EXT_InvalidExceptionMagicNumber ((DWORD)0x880C754DL)

//
// MessageId: E_EXT_InvalidResultCallHandler
//
// MessageText:
//
// Invalid result of EXC_CallHandler
//
#define E_EXT_InvalidResultCallHandler   ((DWORD)0x880C754EL)

//
// MessageId: E_EXT_ControlNotFound
//
// MessageText:
//
// Control not found
//
#define E_EXT_ControlNotFound            ((DWORD)0x880C754FL)

//
// MessageId: E_EXT_ClientSizeNULL
//
// MessageText:
//
// ClientSize is NULL
//
#define E_EXT_ClientSizeNULL             ((DWORD)0x880C7550L)

//
// MessageId: E_EXT_OBJECTCODE_DATACHANGED
//
// MessageText:
//
// OBJECTCODE_DATACHANGED Advice
//
#define E_EXT_OBJECTCODE_DATACHANGED     ((DWORD)0x880C7551L)

//
// MessageId: E_EXT_OBJECTCODE_VIEWCHANGED
//
// MessageText:
//
// OBJECTCODE_VIEWCHANGED Advice
//
#define E_EXT_OBJECTCODE_VIEWCHANGED     ((DWORD)0x880C7552L)

//
// MessageId: E_EXT_DialogTemplate
//
// MessageText:
//
// Error in CDialogTemplate constructor
//
#define E_EXT_DialogTemplate             ((DWORD)0x880C7553L)

//
// MessageId: E_EXT_DispatchIsNull
//
// MessageText:
//
// Dispatch Is NULL
//
#define E_EXT_DispatchIsNull             ((DWORD)0x880C7554L)

//
// MessageId: E_EXT_BlobIsNotString
//
// MessageText:
//
// Blob is not string
//
#define E_EXT_BlobIsNotString            ((DWORD)0x880C7555L)

//
// MessageId: E_EXT_ControlHWNDIsNULL
//
// MessageText:
//
// Control HWND is NULL
//
#define E_EXT_ControlHWNDIsNULL          ((DWORD)0x880C7556L)

//
// MessageId: E_EXT_UnknownHostAddressType
//
// MessageText:
//
// Unknown host address type
//
#define E_EXT_UnknownHostAddressType     ((DWORD)0x880C7557L)

//
// MessageId: E_EXT_TooltipNotFound
//
// MessageText:
//
// Tooltip not found
//
#define E_EXT_TooltipNotFound            ((DWORD)0x880C7558L)

//
// MessageId: E_EXT_LoadXML
//
// MessageText:
//
// Cannot load XML
//
#define E_EXT_LoadXML                    ((DWORD)0x880C7559L)

//
// MessageId: E_EXT_NoInputStream
//
// MessageText:
//
// No Input Stream
//
#define E_EXT_NoInputStream              ((DWORD)0x880C755AL)

//
// MessageId: E_EXT_NoOutputStream
//
// MessageText:
//
// No Output stream
//
#define E_EXT_NoOutputStream             ((DWORD)0x880C755BL)

//
// MessageId: E_InvalidExtendOfNumber
//
// MessageText:
//
// Invalid extend of number
//
#define E_InvalidExtendOfNumber          ((DWORD)0x880C755CL)

//
// MessageId: E_EXT_UnknownStructuredStorageElementType
//
// MessageText:
//
// Unknown Structured Storage element type
//
#define E_EXT_UnknownStructuredStorageElementType ((DWORD)0x880C755DL)

//
// MessageId: E_EXT_UnknownTypeOfVariant
//
// MessageText:
//
// Unknown type of variant
//
#define E_EXT_UnknownTypeOfVariant       ((DWORD)0x880C755EL)

//
// MessageId: E_EXT_DifferentTypeOfVariant
//
// MessageText:
//
// Different type of Variant
//
#define E_EXT_DifferentTypeOfVariant     ((DWORD)0x880C755FL)

//
// MessageId: E_EXT_FontNotFound
//
// MessageText:
//
// Font not found
//
#define E_EXT_FontNotFound               ((DWORD)0x880C7560L)

//
// MessageId: E_EXT_NoAdviseHolder
//
// MessageText:
//
// No Advise Holder
//
#define E_EXT_NoAdviseHolder             ((DWORD)0x880C7561L)

//
// MessageId: E_EXT_OleControlError
//
// MessageText:
//
// OLE Control Error
//
#define E_EXT_OleControlError            ((DWORD)0x880C7562L)

//
// MessageId: E_EXT_UnknownWin32Error
//
// MessageText:
//
// Unknown Win32 Error
//
#define E_EXT_UnknownWin32Error          ((DWORD)0x880C7563L)

//
// MessageId: E_EXT_VarTypeInNotStringCompatible
//
// MessageText:
//
// Variant type is not string-compatible
//
#define E_EXT_VarTypeInNotStringCompatible ((DWORD)0x880C7564L)

//
// MessageId: E_EXT_UnknownSocketsError
//
// MessageText:
//
// Unknown Sockets error
//
#define E_EXT_UnknownSocketsError        ((DWORD)0x880C7565L)

//
// MessageId: E_EXT_InvalidUTF8String
//
// MessageText:
//
// Invalid UTF-8 string
//
#define E_EXT_InvalidUTF8String          ((DWORD)0x880C7566L)

//
// MessageId: E_EXT_UnsupportedVariantType
//
// MessageText:
//
// Unsupported variant type
//
#define E_EXT_UnsupportedVariantType     ((DWORD)0x880C7567L)

//
// MessageId: E_EXT_NoControlWithThisID
//
// MessageText:
//
// No control with this ID
//
#define E_EXT_NoControlWithThisID        ((DWORD)0x880C7568L)

//
// MessageId: E_EXT_NameOfApplicationKeyIsEmpty
//
// MessageText:
//
// Name of application key is empty
//
#define E_EXT_NameOfApplicationKeyIsEmpty ((DWORD)0x880C7569L)

//
// MessageId: E_EXT_AssertFailedLine
//
// MessageText:
//
// Error AssertFailedLine
//
#define E_EXT_AssertFailedLine           ((DWORD)0x880C756AL)

//
// MessageId: E_EXT_Trace
//
// MessageText:
//
// Error Trace
//
#define E_EXT_Trace                      ((DWORD)0x880C756BL)

//
// MessageId: E_EXT_AssertValidObject
//
// MessageText:
//
// Error AssertValidObject
//
#define E_EXT_AssertValidObject          ((DWORD)0x880C756CL)

//
// MessageId: E_EXT_InvalidSpliType
//
// MessageText:
//
// Invalid Split type
//
#define E_EXT_InvalidSpliType            ((DWORD)0x880C756DL)

//
// MessageId: E_EXT_BlackRedTree
//
// MessageText:
//
// Error in black-red tree
//
#define E_EXT_BlackRedTree               ((DWORD)0x880C756EL)

//
// MessageId: E_EXT_XMLError
//
// MessageText:
//
// XML Error
//
#define E_EXT_XMLError                   ((DWORD)0x880C756FL)

//
// MessageId: E_EXT_QueueUserAPC
//
// MessageText:
//
// QueueUserAPC Error
//
#define E_EXT_QueueUserAPC               ((DWORD)0x880C7570L)

//
// MessageId: E_EXT_SignalBreak
//
// MessageText:
//
// Signal BREAK
//
#define E_EXT_SignalBreak                ((DWORD)0x880C7571L)

//
// MessageId: E_EXT_NormalExit
//
// MessageText:
//
// Normal Exit
//
#define E_EXT_NormalExit                 ((DWORD)0x880C7572L)

//
// MessageId: E_EXT_BigNumConversion
//
// MessageText:
//
// BigNum conversion error
//
#define E_EXT_BigNumConversion           ((DWORD)0x880C7573L)

//
// MessageId: E_EXT_DivideByZero
//
// MessageText:
//
// Divide by zero
//
#define E_EXT_DivideByZero               ((DWORD)0x880C7574L)

//
// MessageId: E_EXT_InvalidInteger
//
// MessageText:
//
// Invalid format of Integer
//
#define E_EXT_InvalidInteger             ((DWORD)0x880C7575L)

//
// MessageId: E_EXT_InvalidCast
//
// MessageText:
//
// Invalid Cast
//
#define E_EXT_InvalidCast                ((DWORD)0x880C7576L)

//
// MessageId: E_EXT_MaxTries
//
// MessageText:
//
// Maximum Tries Failed
//
#define E_EXT_MaxTries                   ((DWORD)0x880C7577L)

//
// MessageId: E_EXT_NonEmptyPointer
//
// MessageText:
//
// Non-empty pointer
//
#define E_EXT_NonEmptyPointer            ((DWORD)0x880C7578L)

//
// MessageId: E_EXT_ObjectNotInitialized
//
// MessageText:
//
// Object not initialized
//
#define E_EXT_ObjectNotInitialized       ((DWORD)0x880C7579L)

//
// MessageId: E_EXT_ObjectDisposed
//
// MessageText:
//
// Object disposed
//
#define E_EXT_ObjectDisposed             ((DWORD)0x880C757AL)

//
// MessageId: E_EXT_Dynamic_Library
//
// MessageText:
//
// Dynamic Library error
//
#define E_EXT_Dynamic_Library            ((DWORD)0x880C757BL)

//
// MessageId: E_EXT_CodeNotReachable
//
// MessageText:
//
// CodeNotReachable
//
#define E_EXT_CodeNotReachable           ((DWORD)0x880C757CL)

//
// MessageId: E_EXT_Imaging
//
// MessageText:
//
// Imaging Error
//
#define E_EXT_Imaging                    ((DWORD)0x880C757DL)

//
// MessageId: E_EXT_Arithmetic
//
// MessageText:
//
// Aritmetic error
//
#define E_EXT_Arithmetic                 ((DWORD)0x880C757EL)

//
// MessageId: E_EXT_Overflow
//
// MessageText:
//
// Overlow error
//
#define E_EXT_Overflow                   ((DWORD)0x880C757FL)

//
// MessageId: E_EXT_EncodingNotSupported
//
// MessageText:
//
// Encoding not supported
//
#define E_EXT_EncodingNotSupported       ((DWORD)0x880C7580L)

//
// MessageId: E_EXT_SAT_EmptyStructure
//
// MessageText:
//
// SAT Empty Structure
//
#define E_EXT_SAT_EmptyStructure         ((DWORD)0x880C7581L)

//
// MessageId: E_EXT_Protocol_Violation
//
// MessageText:
//
// Protocol Violation
//
#define E_EXT_Protocol_Violation         ((DWORD)0x880C7582L)

//
// MessageId: E_EXT_New_Protocol_Version
//
// MessageText:
//
// New Unsupported Protocol Verion used
//
#define E_EXT_New_Protocol_Version       ((DWORD)0x880C7583L)

//
// MessageId: E_EXT_RES_1
//
// MessageText:
//
// ReservedMessage1
//
#define E_EXT_RES_1                      ((DWORD)0x880C7584L)

//
// MessageId: E_EXT_FileFormat
//
// MessageText:
//
// Input File Format violated
//
#define E_EXT_FileFormat                 ((DWORD)0x880C7585L)

//
// MessageId: E_EXT_ReadTapeSync
//
// MessageText:
//
// Synchronization error during reading of Tape
//
#define E_EXT_ReadTapeSync               ((DWORD)0x880C7586L)

//
// MessageId: E_EXT_JSON_Parse
//
// MessageText:
//
// JSON Parse error
//
#define E_EXT_JSON_Parse                 ((DWORD)0x880C7587L)

//
// MessageId: E_EXT_CrashRpt
//
// MessageText:
//
// CrashRpt error
//
#define E_EXT_CrashRpt                   ((DWORD)0x880C7588L)

//
// MessageId: E_EXT_JSON_RPC_ParseError
//
// MessageText:
//
// JSON-RPC Parse Error
//
#define E_EXT_JSON_RPC_ParseError        ((DWORD)0xC80F8004L)

//
// MessageId: E_EXT_JSON_RPC_Internal
//
// MessageText:
//
// JSON-RPC Internal Error
//
#define E_EXT_JSON_RPC_Internal          ((DWORD)0xC80F8065L)

//
// MessageId: E_EXT_JSON_RPC_InvalidParams
//
// MessageText:
//
// JSON-RPC Invalid method parameter(s).
//
#define E_EXT_JSON_RPC_InvalidParams     ((DWORD)0xC80F8066L)

//
// MessageId: E_EXT_JSON_RPC_MethodNotFound
//
// MessageText:
//
// JSON-RPC Method not found
//
#define E_EXT_JSON_RPC_MethodNotFound    ((DWORD)0xC80F8067L)

//
// MessageId: E_EXT_JSON_RPC_IsNotRequest
//
// MessageText:
//
// The JSON sent is not a valid Request object.
//
#define E_EXT_JSON_RPC_IsNotRequest      ((DWORD)0xC80F8068L)

//
// MessageId: E_EXT_Zlib
//
// MessageText:
//
// Zlib error
//
#define E_EXT_Zlib                       ((DWORD)0x880CC15CL)

//
// MessageId: E_EXT_DB_NoRecord
//
// MessageText:
//
// No record found for scalar DB query
//
#define E_EXT_DB_NoRecord                ((DWORD)0x880CC1C0L)

//
// MessageId: E_EXT_DB_DupKey
//
// MessageText:
//
// Cannot insert Duplicate Key into Database
//
#define E_EXT_DB_DupKey                  ((DWORD)0x880CC1C1L)

//
// MessageId: E_EXT_DB_Corrupt
//
// MessageText:
//
// Database corruption
//
#define E_EXT_DB_Corrupt                 ((DWORD)0x880CC1C2L)

//
// MessageId: E_EXT_DB_Version
//
// MessageText:
//
// Database created with newer version of software
//
#define E_EXT_DB_Version                 ((DWORD)0x880CC1C3L)

//
// MessageId: E_EXT_DB_InternalError
//
// MessageText:
//
// Internal Error of DB engine
//
#define E_EXT_DB_InternalError           ((DWORD)0x880CC1C4L)

//
// MessageId: E_SOCKS_InvalidVersion
//
// MessageText:
//
// Invalid Version Number (only V4 & V5 are supported)
//
#define E_SOCKS_InvalidVersion           ((DWORD)0x880CC351L)

//
// MessageId: E_SOCKS_IncorrectProtocol
//
// MessageText:
//
// Incorrect bytes in protocol
//
#define E_SOCKS_IncorrectProtocol        ((DWORD)0x880CC352L)

//
// MessageId: E_SOCKS_RejectedBecauseIDENTD
//
// MessageText:
//
// Request rejected because SOCKS server cannot connect to identd on the client
//
#define E_SOCKS_RejectedBecauseIDENTD    ((DWORD)0x880CC353L)

//
// MessageId: E_SOCKS_RejectedOrFailed
//
// MessageText:
//
// Request rejected or failed
//
#define E_SOCKS_RejectedOrFailed         ((DWORD)0x880CC354L)

//
// MessageId: E_SOCKS_DifferentUserIDs
//
// MessageText:
//
// Request rejected because the client program and identd report different user-ids
//
#define E_SOCKS_DifferentUserIDs         ((DWORD)0x880CC355L)

//
// MessageId: E_SOCKS_AuthNotSupported
//
// MessageText:
//
// Server's authentication method does not supported by client
//
#define E_SOCKS_AuthNotSupported         ((DWORD)0x880CC356L)

//
// MessageId: E_SOCKS_BadUserOrPassword
//
// MessageText:
//
// Bad SOCKS Username or Password
//
#define E_SOCKS_BadUserOrPassword        ((DWORD)0x880CC357L)

//
// MessageId: E_PROXY_LongDomainName
//
// MessageText:
//
// Domain name very long
//
#define E_PROXY_LongDomainName           ((DWORD)0x880CC358L)

//
// MessageId: E_PROXY_InvalidAddressType
//
// MessageText:
//
// Invalid address type
//
#define E_PROXY_InvalidAddressType       ((DWORD)0x880CC359L)

//
// MessageId: E_PROXY_VeryLongLine
//
// MessageText:
//
// Very long line
//
#define E_PROXY_VeryLongLine             ((DWORD)0x880CC35AL)

//
// MessageId: E_PROXY_BadReturnCode
//
// MessageText:
//
// Bad return code
//
#define E_PROXY_BadReturnCode            ((DWORD)0x880CC35BL)

//
// MessageId: E_PROXY_ConnectTimeOut
//
// MessageText:
//
// Connect time out
//
#define E_PROXY_ConnectTimeOut           ((DWORD)0x880CC35CL)

//
// MessageId: E_PROXY_NoLocalHosts
//
// MessageText:
//
// No local hosts found
//
#define E_PROXY_NoLocalHosts             ((DWORD)0x880CC35DL)

//
// MessageId: E_PROXY_MethodNotSupported
//
// MessageText:
//
// SOCKS Method not supported
//
#define E_PROXY_MethodNotSupported       ((DWORD)0x880CC35EL)

//
// MessageId: E_PROXY_InvalidHttpRequest
//
// MessageText:
//
// Invalid HTTP request
//
#define E_PROXY_InvalidHttpRequest       ((DWORD)0x880CC35FL)

//
// MessageId: E_SOCKS_Base
//
// MessageText:
//
// Base SOCKS error
//
#define E_SOCKS_Base                     ((DWORD)0x880CF230L)

//
// MessageId: E_SOCKS_GeneralFailure
//
// MessageText:
//
// General SOCKS server failure
//
#define E_SOCKS_GeneralFailure           ((DWORD)0x880CF231L)

//
// MessageId: E_SOCKS_NotAllowedByRuleset
//
// MessageText:
//
// Connection not allowed by ruleset
//
#define E_SOCKS_NotAllowedByRuleset      ((DWORD)0x880CF232L)

//
// MessageId: E_SOCKS_NetworkUnreachable
//
// MessageText:
//
// Network unreachable
//
#define E_SOCKS_NetworkUnreachable       ((DWORD)0x880CF233L)

//
// MessageId: E_SOCKS_HostUnreachable
//
// MessageText:
//
// Host unreachable
//
#define E_SOCKS_HostUnreachable          ((DWORD)0x880CF234L)

//
// MessageId: E_SOCKS_Refused
//
// MessageText:
//
// Connection refused
//
#define E_SOCKS_Refused                  ((DWORD)0x880CF235L)

//
// MessageId: E_SOCKS_TTLExpired
//
// MessageText:
//
// TTL expired
//
#define E_SOCKS_TTLExpired               ((DWORD)0x880CF236L)

//
// MessageId: E_SOCKS_CommandNotSupported
//
// MessageText:
//
// SOCKS command not supported
//
#define E_SOCKS_CommandNotSupported      ((DWORD)0x880CF237L)

//
// MessageId: E_SOCKS_AddressTypeNotSupported
//
// MessageText:
//
// AddressTypeNotSupported
//
#define E_SOCKS_AddressTypeNotSupported  ((DWORD)0x880CF238L)

//
// MessageId: E_SOCKS_Last
//
// MessageText:
//
// Last SOCKS error
//
#define E_SOCKS_Last                     ((DWORD)0x880CF32FL)

//
// MessageId: E_HTTP_Base
//
// MessageText:
//
// HTTP error code
//
#define E_HTTP_Base                      ((DWORD)0x80190000L)

