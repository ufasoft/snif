/*###########################################################################################################################
# Copyright (c) 1997-2012 Ufasoft   http://ufasoft.com   mailto:support@ufasoft.com                                         #
#                                                                                                                           #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License #
# as published by the Free Software Foundation; either version 3, or (at your option) any later version.                    #                                                          #
#                                                                                                                           #
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied        #
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.     #
#                                                                                                                           #
# You should have received a copy of the GNU General Public License along with this program;                                #
# If not, see <http://www.gnu.org/licenses/>                                                                                #
###########################################################################################################################*/

#pragma once

typedef unsigned long ulong;

// Common ICQ protocol definitions (based on OSCAR specification)

enum EMessage
{
	MESSAGE_ERROR					= 0x01,
	MESSAGE_EVIL_REQUEST	=	0x08,
	MESSAGE_EVIL_REPLY		= 0x09,
	MESSAGE_MISSED_CALLS	= 0x0A,
	MESSAGE_CLIENT_ERROR	= 0x0B,
	MESSAGE_HOST_ACK			= 0x0C
};

enum ESnacType
{
	FAM_GENERIC = 1,
	FAM_LOCATION,				// 2
	FAM_BUDDY,					// 3
	FAM_MESSAGE,				// 4
	FAM_ADVERTISE,			// 5
	FAM_INVITE,					// 6
	FAM_ADMIN,					// 7
	FAM_POPUP,					// 8
	FAM_PRIVACY,				// 9
	FAM_USER_LLOKUP,		// 0x0A  (obsolete)
	FAM_STATS,					// 0x0B
	FAM_TRANSLATE,      // 0x0C
	FAM_CHATNAV,				// 0x0D
	FAM_CHAT,						// 0x0E
	FAM_USER_SEARCH,		// 0x0F,
	FAM_BUDDY_ICONS,		// 0x10
	FAM_SSI = 0x13,
	FAM_EXT = 0x15,
	FAM_AUTH = 0x17,

	SRV_ONLINExINFO = MAKELONG(0xF, FAM_GENERIC),

	SRV_USER_ONLINE = MAKELONG(0xB, FAM_BUDDY),
	SRV_USER_OFFLINE = MAKELONG(0xC, FAM_BUDDY),

	CLI_SEND_ICBM		= MAKELONG(6, FAM_MESSAGE),
	SRV_CLIENT_ICBM = MAKELONG(7, FAM_MESSAGE),
	CLI_ICBM_SENDxACK = MAKELONG(0xB, FAM_MESSAGE),

	CLI_META_REQ =		MAKELONG(2, FAM_EXT),
	SRV_META_REPLY =	MAKELONG(3, FAM_EXT),

	SNAC_SIGNON_ERROR				= MAKELONG(1, FAM_AUTH),
	SNAC_SIGNON_LOGIN_REQUEST		= MAKELONG(2, FAM_AUTH),
	SNAC_SIGNON_LOGIN_REPLY			= MAKELONG(3, FAM_AUTH),
	SNAC_SIGNON_REGISTRATION_REQ	= MAKELONG(4, FAM_AUTH),
	SNAC_SIGNON_NEW_UIN				= MAKELONG(5, FAM_AUTH),
	SNAC_SIGNON_AUTH_REQUEST		= MAKELONG(6, FAM_AUTH),
	SNAC_SIGNON_AUTH_KEY			= MAKELONG(7, FAM_AUTH),
	SNAC_SIGNON_REQUEST_IMAGE		= MAKELONG(0xC, FAM_AUTH),
	SNAC_SIGNON_REG_AUTH_IMAGE		= MAKELONG(0xD, FAM_AUTH),

};

enum EMesageType
{
	MTYPE_PLAIN = 1,
	MTYPE_CHAT,			// 2
	MTYPE_FILEREQ,  // 3
	MTYPE_URL,      // 4
	MTYPE_AUTHREQ = 6,
	MTYPE_AUTHDENY, // 7
	MTYPE_AUTHOK,   // 8
	MTYPE_SERVER,   // 9
	MTYPE_ADDED = 0x0C,
	MTYPE_WWP,      // 0x0D
	MTYPE_EEXPRESS, // 0x0E
	MTYPE_CONTACTS = 0x13,
	MTYPE_PLUGIN = 0x1A,
	MTYPE_AUTOAWAY = 0xE8,
	MTYPE_AUTOBUSY, // 0xE9,
	MTYPE_AUTONA,   // 0xEA
	MTYPE_AUTODND,  // 0xEB
	MTYPE_AUTOFFC   // 0xEC
};

enum EExtType {
	SRV_OFFLINE_MESSAGE = 0x41,
	CLI_META_INFO_REQ = 0x07D0
};

enum EExtSubtype {
	CLI_SEND_SMS  = 0x1482
};

enum ETlv {
	TLV_SCREEN_NAME				= 1,
	TLV_PASSWORD					= 2,
	TLV_CLIENT_ID_STRING	= 3,
	TLV_SERVER_ENDPOINT		= 5,
	TLV_AUTH_COOKIE				= 6,
	TLV_CLIENT_COUNTRY		= 0x0E,
	TLV_CLIENT_LANGUAGE		= 0x0F,
	TLV_DISTRIBUTION_NUMBER = 0x14,
	TLV_CLIENT_ID					= 0x16,
	TLV_CLIENT_MAJOR_VER	= 0x17,
	TLV_CLIENT_MINOR_VER	= 0x18,
	TLV_CLIENT_LESSER_VER	= 0x19,
	TLV_CLIENT_BUILD_NUMBER	= 0x1A,
	TLV_MD5	= 0x25,
	TLV_EXTENSION_DATA    = 0x2711
};

enum EPeer {
	PEER_INIT			=	0xFF,
	PEER_INITACK	= 1,
	PEER_MSG			= 2,
	PEER_MSGINIT	= 3
};

#pragma pack(push, 1)

struct HttpIcqHeader {
	Nuint16_t len;
	BYTE unk[3];
	BYTE type; // =5 for FLAP
	BYTE unk2[8];
};

struct Flap {
	BYTE		start;			// Packet start = 0x2A 
	BYTE		chan;				// Communication channel
	Nuint16_t	Seq;				// Sequence number
	Nuint16_t Length;			// Data length
};

struct Snac {
	Nuint16_t Family;
	Nuint16_t Subtype;
	Nuint16_t flags;
	DWORD		seq;				// Snac Sequence id
};

struct MsgHeader {	
	DWORD		timestamp;		// Seems to be a time stamp in 1/1500 sec since 8am of that Sunday.
	// ((time(NULL) - (8*60*60)) + DayOfWeek*60*60*24)) * 1500 
	DWORD		msgid;			// 
	Nuint16_t	msg_channel;				// 0x01 - Old type, 0x02 - special, 0x04 - new type
};

struct CTlvExtensionData {
	WORD	len;
	WORD	ver;
	Guid	guid;
	WORD unk1;
	DWORD client_capabilities;
	BYTE unk2;
	WORD	counter;	
	WORD	lendata;
};

struct SOfflineMessage {
	DWORD SenderUin;
	WORD Year;
	BYTE Month,
		Day,
		Hour,
		Minute,
		Type,
		Flags;
};

class MBody {
public:
	ushort	warning;
	ushort	count;			// Количество последующих TLV

	MBody()
		:	warning(0)
		,	count(0)
	{}
};

struct SIcqPeerInit {
	ushort	ver;
	ushort	len;
	ulong	destuin;
	ushort	unk;
	ulong	ourport;
	ulong	ouruin;
	ulong	extip;
	ulong	intip;
	uchar	tcpflag;
	ulong	ourport2;
	ulong	cookie;
	ulong	unk2[3];
};

enum EMsgCmd {
	MSGCMD_CANCEL = 2000,  // 0x07D0
	MSGCMD_ACK = 2010,     // 0x07DA
	MSGCMD_NORMAL = 2030   // 0x07EE
};

struct SIcqPeerMsg {
	DWORD crc;
	WORD cmd;
	WORD m_unk1;
	WORD seq;
	DWORD unk2[3];
	WORD	msgtype;
	WORD	status;
	WORD	flags;
	WORD	msglen;	// Message Follows
};

#pragma pack(pop)

#include <initguid.h>
DEFINE_GUID(GUID_MESSAGE_CAPABILITY	,0x49134609, 0x7f4C, 0xD111, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00);
DEFINE_GUID(GUID_CAP_OSCAR_FILE		,0x43134609, 0x7f4C, 0xD111, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00);
DEFINE_GUID(GUID_MESSAGE_UTF8		,0x0946134E, 0x4C7F, 0x11D1, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00);

DEFINE_GUID(GUID_MGTYPE_MESSAGE		, 0x05736BBE, 0xC20F, 0x4F10, 0xA6, 0xDE, 0x4D, 0xB1, 0xE3, 0x56, 0x4B, 0x0E);
DEFINE_GUID(GUID_MGTYPE_STATUSMSGEXT, 0xBC181A81, 0x6C0E, 0x4718, 0xA5, 0x91, 0x6F, 0x18, 0xDC, 0xC7, 0x6F, 0x1A);
DEFINE_GUID(GUID_MGTYPE_FILE		, 0xD9122DF0, 0x9130, 0x11D3, 0x8D, 0xD7, 0x00, 0x10, 0x4B, 0x06, 0x46, 0x2E);
DEFINE_GUID(GUID_MGTYPE_WEBURL		, 0x72581C37, 0x87E9, 0x11D4, 0xA4, 0xC1, 0x00, 0xD0, 0xB7, 0x59, 0xB1, 0xD9);
DEFINE_GUID(GUID_MGTYPE_CONTACTS	, 0x467D0E2A, 0x7676, 0x11D4, 0xBC, 0xE6, 0x00, 0x04, 0xAC, 0x96, 0x1E, 0xA6);
DEFINE_GUID(GUID_GREETING_CARD		, 0x483BE501, 0xE42A, 0x11D1, 0xB6, 0x79, 0x00, 0x60, 0x97, 0xE1, 0xE2, 0x94);
DEFINE_GUID(GUID_MGTYPE_CHAT		, 0xB220F7BF, 0x8E37, 0x11D4, 0xBD, 0x28, 0x00, 0x04, 0xAC, 0x96, 0xD9, 0x05);
DEFINE_GUID(GUID_MGTYPE_SMS_MESSAGE , 0x00F6280E, 0xE711, 0x11D3, 0xbc, 0xf3, 0x00, 0x04, 0xac, 0x96, 0x9d, 0xc2);
DEFINE_GUID(GUID_MGTYPE_XTRAZ_SCRIPT, 0xEFB3603B, 0x2AD8, 0x456C, 0xA4, 0xE0, 0x9C, 0x5A, 0x5E, 0x67, 0xE8, 0x65);




