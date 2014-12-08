/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include <el/libext/ext-http.h>

#include "msgan.h"
#include "icq.h"

#if UCFG_SNIF_USE_TOR
#	include <../../foreign/tor/tor.h>
#endif

namespace Snif {

class IcqAnalyzer;
class IcqAnalyzerStream;

enum EIcqPacketType {
	ICQ_BAD_PACKET,
	ICQ_TO_DATA,
	ICQ_FROM_DATA,
	ICQ_SNAC,
	ICQ_CHAN,
	ICQ_UNKNOWN,
	ICQ_P2P,
	ICQ_P2P_MESSAGE,
	ICQ_P2P_INIT,
	ICQ_INIT,
	ICQ_DISCONNECT
};

#define MESSAGE_ACK	0x0B

#ifdef _DEBUG

ostream& operator<<(ostream& os, const Flap& flap) {
	return os << "FLAP chan: "  << hex << int(flap.chan) << " seq: " << flap.Seq << " length: " << flap.Length << dec;
}

ostream& operator<<(ostream& os, const Snac& snac) {
	return os << hex << "SNAC fam: " << snac.Family << " type: " << snac.Subtype << " seq: " << snac.seq << dec;
}

#endif

class TLV : public CPersistent {
public:
	UInt16	type;
	Blob	data;

	TLV()
		:	type(0)
	{}

	String ToString() const { return String((const char*)data.constData(), data.Size); }
	
	void Read(const BinaryReader& rd) override {
		WORD w, len;
		rd >> w >> len;
		type = ntohs(w);
		size_t size = ntohs(len);
		data = Blob(0, size);
		rd.Read(data.data(), size);
		
		TRC(2, "TLV Type = " << hex << type);
	}

	bool Get(const BinaryReader& rd) {
		bool r = !rd.BaseStream.Eof();
		if (r)
		    Read(rd);
		return r;
	}

	static vector<TLV> ReadAll(const BinaryReader& rd) {
		vector<TLV> r;
		for (TLV tlv; tlv.Get(rd);)
			r.push_back(tlv);
		return r;
	}
};




class AsciizString : public CPersistent {
public:
	Blob m_blob;

	AsciizString(bool bBigEndian = false)
		:	m_bBigEndian(bBigEndian)
	{
	}

	void Read(const BinaryReader& rd) override {
		WORD len = rd.ReadUInt16();
		if (m_bBigEndian)
			len = ntohs(len);
		char *p = (char*)alloca(len);
		rd.Read(p, len);
		if (!len)
			return;
		if (p[len-1])
			Throw(E_FAIL);
		m_blob = Blob(p, len-1);
	}

	String ToString() { return g_encMessage->GetChars(m_blob); }
private:
	bool m_bBigEndian;
};

String ReadUin(const BinaryReader& rd) {
	byte len = rd.ReadByte();
	char *uin = (char*)alloca(len);
	rd.Read(uin, len);
	return String(uin, len);
}

//!!!R static Regex s_reHtmlTags("<[^>]*>");

class ICBMBase : public CPersistent {
public:
	MsgHeader Header;
	String Uin;
	String Text;

	void ReadBase(const BinaryReader& rd) {
		rd.ReadStruct(Header);
		Uin = ReadUin(rd);
	}

	void ReadExtensionData(const BinaryReader& rd) {
		if (rd.BaseStream.Length-rd.BaseStream.Position < sizeof(CTlvExtensionData))
			return; //!!!
		try {
			CTlvExtensionData extData;
			rd.ReadStruct(extData);
			rd.Read(0, extData.lendata);
			if (extData.guid == GUID_NULL) {
				BYTE msgType, msgFlags;
				WORD status, priority;
				AsciizString az;
				rd >> msgType >> msgFlags >> status >> priority;
				az.Read(rd);

				TRC(1, "msgType= " << hex << (int)msgType);

				switch (msgType) {
				case MTYPE_PLAIN: //!!! if status == 4 may be bitmap
					{
						bool bUtf8 = false;
						if (rd.BaseStream.Length-rd.BaseStream.Position >= 8) {
							try {
								DWORD color, background, lenGuid;
								rd >> color >> background;
								if (!rd.BaseStream.Eof()) {
									rd >> lenGuid;
									if (lenGuid > 100)
										Throw(E_FAIL);
									char *pg = (char*)alloca(lenGuid);
									rd.Read(pg, lenGuid);
									bUtf8 = Guid(String(pg, lenGuid))==GUID_MESSAGE_UTF8;
								}
							} catch (RCExc) {
							}
						}
//!!!R #if 1//!!!D
//!!!R 						cout << "bUtf: " << (bUtf8?1:0) << endl;
//!!!R #endif
						Text = bUtf8 ? UTF8Encoding().GetChars(az.m_blob) : az.ToString();						
					}
					break;
				case MTYPE_PLUGIN:
					{
//!!!						WORD len;
//!!!						ms >> len;
//!!!						ms.ReadBuffer(0, len);
						WORD lenInfo, qt;
						DWORD lenPluginName;
						Guid guid;
						rd >> lenInfo >> guid >> qt >> lenPluginName;
						if (lenPluginName >= 100)
							break;
						char *szPluginName = (char*)alloca(lenPluginName+1);
						memset(szPluginName, 0, lenPluginName+1);
						rd.Read(szPluginName, lenPluginName);
						if (guid == GUID_MGTYPE_XTRAZ_SCRIPT)
							break;
						DWORD dw, dw2;
						rd >> dw >> dw2;
						if (dw2 > 10000)
							Throw(E_FAIL);//!!!
						if (guid == GUID_MGTYPE_MESSAGE) {
							byte stub[11];
							rd.Read(stub, sizeof stub);
							UInt32 rtfSize = rd.ReadUInt32();
							char *buf = (char*)alloca(rtfSize);
							rd.Read(buf, rtfSize);
							Text = String(buf, rtfSize);
							Text = RtfToText(Text);
						} else if (guid == GUID_MGTYPE_STATUSMSGEXT) {
						} else {
							char *buf = (char*)alloca(dw2);
							rd.Read(buf, dw2);
							Text = String(buf, dw2);
							Text = HtmlToPlain(Text); //!!! only for channel 2
						}
					}
					break;
				default:
					Text = az.ToString();
				}
			}
		} catch (RCExc) {
		}
	}
};

class ICBM : public ICBMBase {
public:
	CBool m_bFromServer;
	String OurUin;
	
	void Read(const BinaryReader& rd) override;
};

static const BYTE client_check_data[] =
{
  "As part of this software beta version Mirabilis is granting a limited access to the ICQ network, "
  "servers, directories, listings, information and databases (\"ICQ Services and Information\"). "
	"The ICQ Service and Information may databases (\"ICQ Services and Information\"). "
	"The ICQ Service and Information may\0"
};

class IcqMessage : public Message {
public:
	IcqMessage();
};

class IcqFileMessage : public IcqMessage, public FileTransfer {
	typedef IcqMessage base;
public:
	String Filename;
	FileStream m_stm;

	void Finish() {
		Text = "File Transfer: "+Filename;
		base::Finish();
	}
};

class IcqUser : public User {
//!!!	void PostLoad();
public:	
	void Finish(Message *msg) {
		msg->Finish();
		delete msg;
	}
	static IcqUser *GetByUin(RCString uin, const IPAddress& clientIP = IPAddress());
	static ptr<User> FindByPhone(RCString phone);
	IcqUser(RCString uin = "", const IPAddress& clientIP = IPAddress());
};

class IcqP2pPacket {
public:
	String m_uin;
	String m_text;
	uint m_type;
	String m_our_uin;
	String m_our_pass;
	String m_peer_uin;
public:
	IcqP2pPacket() : m_type(0)
	{}

	bool decrypt_p2p(Blob& blob, DWORD version) {
  	unsigned long key, B1, M1, check;
		unsigned int i;
		unsigned char X1, X2, X3;
		unsigned char *buf = (unsigned char*) blob.data();
		unsigned char bak[6];
		size_t size = blob.Size;
		unsigned long offset;

		if (version < 4)
			return true;  // no decryption necessary.

		switch(version) {
			case 4:
			case 5:
				offset = 6;
				break;
			case 7:
			case 8:
			case 6:
			default:
				offset = 0;
		}

		
		if (version > 6) {		// AOL
		}

		// backup the first 6 bytes
		if (offset)
			for (i=0; i<6; i++)
				bak[i] = buf[i];

		// retrieve checkcode
		check = (buf[offset+3]<<24)|(buf[offset+2]<<16)|(buf[offset+1]<<8)|(buf[offset+0]);

		TRC(1, "size " << dec << (DWORD)size << " check " << hex << check << dec);

		// main XOR key
		key = 0x67657268 * (DWORD)size + check;

		for (i=4; i<(size+3)/4; i+=4) {
			DWORD nHex = key + client_check_data[i&0xFF];
			buf[i+0] ^= nHex&0xFF;buf[i+1] ^= (nHex>>8)&0xFF;
			buf[i+2] ^= (nHex>>16)&0xFF;buf[i+3] ^= (nHex>>24)&0xFF;
		}

		// retrive validate data
		if (offset) {
			// in TCPv4 are the first 6 bytes unencrypted
			// so restore them
			for(i=0;i<6;i++) buf[i] = bak[i];
			B1 = (buf[offset+4]<<24)|(buf[offset+6]<<16)|(buf[2]<<8)|buf[0];
		}
		else
			B1 = (buf[4]<<24) | (buf[6]<<16) | (buf[4]<<8) | (buf[6]<<0);

		// special decryption
		B1 ^= check;

		// validate packet
		M1 = (B1 >> 24) & 0xFF;
		if (M1 < 10 || M1 >= size) {
			TRC(1, "range check failed, M1 is " << hex << M1 << dec);
			return false;
		}

		X1 = buf[M1] ^ 0xFF;
		if (((B1 >> 16) & 0xFF) != X1) {
			TRC(1, "M1 is " << hex << M1);
			TRC(1, "calculated X1 " << hex << X1 << " != " << ((B1 >> 16) & 0xFF) << dec);
			return false;
		}

		X2 = BYTE((B1 >> 8) & 0xFF);
		if (X2 < 220) {
			X3 = client_check_data[X2] ^ 0xFF;
			if ((B1 & 0xFF) != X3) {
				TRC(1, "calculated X3 " << hex << X3 << " does not match B1 " << (B1 & 0xFF) << dec);
				return false;
			}
		}

		return true;
	}

	void process_p2pinit(CMemReadStream& stm) {
		SIcqPeerInit p2pinit;
		BinaryReader(stm).ReadStruct(p2pinit);
		m_our_uin = Convert::ToString(p2pinit.ouruin);			
		m_peer_uin = Convert::ToString(p2pinit.destuin);
	}

	void process_p2pmessage(CMemReadStream& stm) {
		SIcqPeerMsg  p2pmsg;
		BinaryReader rd(stm);
		rd.ReadStruct(p2pmsg);
		switch (p2pmsg.cmd) {
		case MSGCMD_NORMAL:
			{
				char *_text = (char *) alloca(p2pmsg.msglen );
				rd.Read( _text, p2pmsg.msglen );
				m_text = String((char *) _text, p2pmsg.msglen );
			}
			break;
		}
	}

	void Parse(const ConstBuf& data) {
		m_type = ICQ_P2P;	
		CMemReadStream stm(data);
		BinaryReader rd(stm);
		switch (byte type = rd.ReadByte())
		{
		case PEER_INIT:
			TRC(1, "PEER_INIT");
			process_p2pinit(stm);
			m_type = ICQ_P2P_INIT;
			break;
		case PEER_INITACK:
			TRC(1, "PEER_INITACK");
			break;
		case PEER_MSG:
			TRC(1, "PEER_MSG");
			{
				Blob blob(data.P+1, data.Size-1);
				if (decrypt_p2p(blob, 7)) {			 	// XXX: Version check !!!
					CMemReadStream brs(blob);
					process_p2pmessage(brs);
					m_type = ICQ_P2P_MESSAGE;
				} else
					TRC(0, "Decrypt P2P failed!"); //XXX: Throw an exception here
			}
			break;
		case PEER_MSGINIT:
			TRC(1, "PEER_MSGINIT");
		}
	}
};

class IcqP2pAnalyzerStream : public AnalyzerStream {
public:
	IcqP2pAnalyzerStream() {
		m_wanted = 5;
		m_state = ASTATE_NEED_MORE;
	}
private:
	void ParsePacket(const ConstBuf& mb);
	void Process(const ConstBuf& data) override;

	size_t m_rsize;
};

class IcqP2pAnalyzer: public Analyzer {
	uint m_rsize;
public:
	ptr<class User> User,
		        PeerUser;

	ptr<IcqFileMessage> FileMessage;

	IcqP2pAnalyzerStream m_outStm, m_inStm;

	IcqP2pAnalyzer();
	bool TryRecognize() override;
};

class IcqPacket {
public:
	static IcqPacket *s_curPacket;  //!!!non-ThreadSafe

	IcqAnalyzer& m_icqAnalyzer;

	Snac m_snac;
	MBody m_body;
	String m_our_uin;
	String m_our_pass;
	String m_peer_uin;
	ptr<class User> User;
	ICBM icbm;
//!!!	Blob m_cookie;

	EIcqPacketType Type;
	ESnacType SnacType;

	IcqPacket(IcqAnalyzer& ia)
		:	m_icqAnalyzer(ia)
		,	Type(ICQ_BAD_PACKET)
	{}

	void ProcessHello(const BinaryReader& rd);
	void ProcessAuthKey(const BinaryReader& rd);
	void ProcessLoginRequest(const BinaryReader& rd);
	void ProcessDisconnect(const BinaryReader& rd);

	class MetaData : public CPersistent 	{
	public:
		String Uin;
		WORD Type;
		class Blob Blob;

		void Read(const BinaryReader& rd) override {
			TLV tlv;
			tlv.Read(rd);
			if (tlv.type != 1)
				Throw(E_FAIL);
			CMemReadStream bs(tlv.data);
			BinaryReader brd(bs);
			WORD len, seq;
			DWORD uin;
			brd >> len >> uin >> Type >> seq;
			Uin = Convert::ToString(uin);
			if (len < 8)
				Throw(E_FAIL);
			Blob = Ext::Blob(0, len-8);
			brd.Read(Blob.data(), Blob.Size);
		}
	};

	void ProcessMetaReq(const BinaryReader& rd) {
		TRC(1, "CLI_META_REQ");
		MetaData metaData;
		metaData.Read(rd);
		switch (metaData.Type)
		{
		case CLI_META_INFO_REQ:
			{
				CMemReadStream bs(metaData.Blob);
				BinaryReader brd(bs);
				switch (UInt16 subtype =brd.ReadUInt16())
				{
				case CLI_SEND_SMS:
					{
						brd.Read(0, 22);
						AsciizString az(true);
						brd >> az;
#if UCFG_XML
						ptr<IcqMessage> m = new IcqMessage;
						istringstream is((const char*)az.m_blob.constData());
 			    		XmlTextReader r(is);
						if (r.ReadToFollowing("destination")) {							
							m->To = IcqUser::FindByPhone(r.ReadString());
			     			if (r.ReadToFollowing("text")) {
								m->Text = r.ReadString();
								m->From = IcqUser::GetByUin(metaData.Uin);			     			
								m->Finish();
							}
						}
#endif
					}
					break;
				}
			}
			break;
		}
	}

	void ProcessMetaReply(const BinaryReader& rd) {
		TRC(1, "SRV_META_REPLY");
		MetaData metaData;
		rd >> metaData;
		switch (metaData.Type) {
		case SRV_OFFLINE_MESSAGE:
			CMemReadStream bs(metaData.Blob);
			BinaryReader brd(bs);
			SOfflineMessage msg;
			brd.ReadStruct(msg);
			AsciizString az;
			brd >> az;
			ptr<IcqMessage> m = new IcqMessage;
			m->DateTime = DateTime(msg.Year, msg.Month, msg.Day, msg.Hour, msg.Minute);
			m->Text = az.ToString();
			m->From = IcqUser::GetByUin(Convert::ToString(msg.SenderUin));
			m->To = IcqUser::GetByUin(metaData.Uin);
			m->Finish();
			break;
		}
	}

	void Parse(const ConstBuf& data, IcqAnalyzerStream *ias);
};

class IcqAnalyzerStream : public AnalyzerStream {
public:
	IcqAnalyzerStream() {
		m_state = ASTATE_NEED_MORE;
		m_wanted = sizeof(Flap);
	}

	void ParsePacket(const ConstBuf& mb);
	void Process(const ConstBuf& data) override;
private:
	CBool m_bWasSYN;

	void MemorizeServer();
};

IcqPacket *IcqPacket::s_curPacket;  //!!!non-ThreadSafe

class IcqAnalyzer : public Analyzer {
public:
	static IcqAnalyzer *s_curIcqAnalyzer; //!!!non-ThreadSafe

	Blob m_authKey;

	CBool m_bRecognized;

	IcqAnalyzerStream m_outStm, m_inStm;

	IcqAnalyzer();
	ptr<User, Interlocked> EnsureUser(RCString uin);
	bool TryRecognize() override;

	virtual IPAddress GetSrcAddress() {
		return ConnectionManager::I->m_lastSrcEndPoint.Address;
//!!!		return m_bSwapped ? m_ci->DstEndPoint : m_ci->SrcEndPoint;
	}
};

IcqAnalyzer *IcqAnalyzer::s_curIcqAnalyzer; //!!!non-ThreadSafe

class MessageBlock {
public:
	DWORD Timestamp;
	DWORD Cookie;
	String Text;

	bool operator<(const MessageBlock& mb) const {
		if (Timestamp < mb.Timestamp)
			return true;
		else if (Timestamp == mb.Timestamp) {
			if (Cookie < mb.Cookie)
				return true;
			else if (Cookie == mb.Cookie)
				return Text < mb.Text;
		}
		return false;
	}

	bool operator==(const MessageBlock& mb) const {
		return !(_self < mb) && !(mb < _self);
	}
};

} namespace EXT_HASH_VALUE_NS {
size_t hash_value(const Snif::MessageBlock& mb) {
    return hash<DWORD>()(mb.Timestamp) ^ hash<DWORD>()(mb.Cookie) ^ hash<String>()(mb.Text);
}
}
EXT_DEF_HASH(Snif::MessageBlock)
namespace Snif {

class IcqHttpAnalyzer : public IcqAnalyzer {
public:
	CPointer<CConnectionInfo> m_extCi;

	StreamClient m_client0, m_client1;

	IcqHttpAnalyzer()
		:	m_client0(0, false)
		,	m_client1(0, true)
	{
		m_bRecognized = true;
		m_arStm[0]->SetStreamClient(&m_client0);
		m_arStm[1]->SetStreamClient(&m_client1);
	}

	IPAddress GetSrcAddress() {
		return ConnectionManager::I->m_lastSrcEndPoint.Address;
	//!!!	return m_extCi->SrcEndPoint; 
	}

	void ProcessHttpMessage(const ConstBuf& mb, int dir) {
		if (mb.Size < sizeof(HttpIcqHeader))
			return;
#ifdef X_DEBUG //!!!D
		if (mb.m_len == 70)
			dir = dir;
#endif
		CMemReadStream stm(mb);
		BinaryReader rd(stm);
		while (!stm.Eof()) {
			HttpIcqHeader hdr;
			rd.ReadStruct(hdr);
			size_t len = hdr.len-sizeof(hdr)+2;
			Blob block(0, len);
			rd.Read(block.data(), len);	
			if (hdr.type != 5 && block.constData()[0] == '*')
				dir = dir;
			if (hdr.type == 5) {
				Blob& blob = (dir ? &m_client1 : &m_client0)->m_blob;
				blob.Replace(blob.Size, 0, block);
				m_arStm[dir]->Process();
				if (blob.Size == 2) //!!!D
					dir = dir;
			}
		}
#ifdef _DEBUG //!!!D
		if (m_arStm[dir]->m_wanted > 10000)
			dir = dir;
#endif
	}
};


/*!!!
class CSidWrap : public String
{
public:
	CSidWrap(RCString s = "")
		:	String(s)
	{}

	CSidWrap(const CSidWrap& sw)
		:	String(sw),
			An(sw.An)
	{}

	ptr<IcqHttpAnalyzer> An;
};


inline size_t hash_value(const CSidWrap& sw) {
    return hash_value(static_cast<const String&>(sw));
}*/

static regex s_reSid("sid=(\\w+)");

typedef LruMap<Blob, ptr<User> > CookieCache;

class IcqAnalyzerClass : public AnalyzerClass<IcqAnalyzer>, HttpSubscription {
public:
	static IcqAnalyzerClass *I;

	set<IPAddress> IcqServers;
	list<IPEndPoint> LoginCookies;
	
	CookieCache AuthCookies;

	LruCache<MessageBlock> LastMessages;

	typedef LruMap<IPEndPoint, ptr<IcqFileMessage> >  DccLruMap;
	DccLruMap DccEndpoints;

	IcqAnalyzerClass() {
		EXT_LOCK (s_cs) {
			I = this;
			Priority = 10;
			Create("ICQ");
		}
	}

	~IcqAnalyzerClass() {
		EXT_LOCK (s_cs) {
			I = 0;
		}
	}

	deque<String> m_qQuery;
	vector<pair<String, ptr<User> > > m_arResolved;

	void AddICQQuery(RCString uin) {
		static regex s_reDigits("\\d+");
		if (!regex_match(uin.c_str(), s_reDigits))
			return;
		EXT_LOCK (s_cs) {
			if (find(m_qQuery.begin(), m_qQuery.end(), uin) == m_qQuery.end())
				m_qQuery.push_back(uin);
		}
	}

	void InThreadExecute() override;
private:
	typedef LruMap<String, ptr<IcqHttpAnalyzer> > CHttpAnalyzers;
	CHttpAnalyzers HttpAnalyzers;

	static recursive_mutex s_cs;

	void OnReceived(HttpDialog *dialog) {
		HttpDialog& d = *dialog;
		if (d.Response.Headers.Get("Content-Type") == "AIM/HTTP") {
			String uri = d.Request.RequestUri;
			cmatch m;
			if (regex_search(uri.c_str(), m, s_reSid)) {
				TRC(2, "ICQ Analyzer: Process http request");
				pair<CHttpAnalyzers::iterator, bool> ii = HttpAnalyzers.insert(CHttpAnalyzers::value_type(String(m[1]), ptr<IcqHttpAnalyzer>(nullptr)));
				if (ii.second)
					ii.first->second.first = new IcqHttpAnalyzer;
				ptr<IcqHttpAnalyzer> ha = ii.first->second.first;
				ha->m_extCi = d.m_ci;
				ha->ProcessHttpMessage(d.Request.Data, 0);
				ha->ProcessHttpMessage(d.Response.Data, 1);
			}
		}
	}

friend class CIcqMessageAnalyzerClass;
};

recursive_mutex IcqAnalyzerClass::s_cs;

void ICBM::Read(const BinaryReader& rd) {
	ReadBase(rd);
	if (m_bFromServer) {
		WORD warn, tlbs;
		rd >> warn >> tlbs;
	}
	Blob msgData2,
				msgData5;
	vector<TLV> tlvs = TLV::ReadAll(rd);
	for (int k=0; k<tlvs.size(); ++k) {
		const TLV& tlv = tlvs[k];
		switch (tlv.type) {
			case 2:
				msgData2 = tlv.data;
				break;	
			case 5:
				msgData5 = tlv.data;
				break;
		}
	}
	UInt16 chan = Header.msg_channel;

	TRC(1, "msg_channel = " << chan);

	switch (chan) {
	case 1:
		{
			CMemReadStream bs(msgData2);
			vector<TLV> tlvs1 = TLV::ReadAll(BinaryReader(bs));
			for (int k=0; k<tlvs1.size(); ++k) {
				const TLV& tlv = tlvs1[k];
				switch (tlv.type) {
				case 0x101:
					{
						CMemReadStream ms(tlv.data);
						WORD charset, langid;
						BinaryReader(ms) >> charset >> langid;
						Blob msg(tlv.data.constData()+4, tlv.data.Size-4);
						size_t len = msg.Size;
						if (ntohs(charset) == 2) {		// UNICODE
							char *dest = (char *) alloca(len);
							for(uint i=0; i<len; i+=2) {
								dest[i] = msg.constData()[i+1];
								dest[i+1] = msg.constData()[i];
							}
							Text = String( (const UInt16 *) dest, len / 2);
							TRC(1, "msg: " << Text);
						} else {
							Encoding *enc = g_encMessage;
#ifdef WIN32
							static CodePageEncoding s_ansiEncoding(CP_ACP);
							if (!g_bEncChanged)
								enc = &s_ansiEncoding;
#endif
							Text = enc->GetChars(msg);
						}
						Text = HtmlToText(Text);
					}
					break;
				}
			}
		}
		break;
	case 2:
		{
			CMemReadStream bs(msgData5);
			BinaryReader brd(bs);
			WORD msgType;
			u_int64_t msgIdCookie;
			brd >> msgType >> msgIdCookie;

			TRC(1, "msgType= " << hex << msgType);

			Guid caps;
			brd.ReadStruct(caps);
			BinaryReader rdbs(bs);
			if (caps == GUID_MESSAGE_CAPABILITY) {
				for (TLV t; t.Get(rdbs);) {
					TRC(1, "TLV: " << hex << t.type << dec);
					switch (t.type) {
					case TLV_EXTENSION_DATA:
						CMemReadStream bsr(t.data);
						ReadExtensionData(BinaryReader(bsr));
						break;
					}
				}
			} else if (caps == GUID_CAP_OSCAR_FILE) {
				IPEndPoint ep;
				String filename;

				vector<TLV> tlvs = TLV::ReadAll(rdbs);
				for (int k=0; k<tlvs.size(); ++k) {
					const TLV& tlv = tlvs[k];

					switch (tlv.type) {
						case 3:
							ep.Address = IPAddress(*(UInt32*)tlv.data.constData());
							break;	
						case TLV_SERVER_ENDPOINT:
							ep.Port = ntohs(*(UInt16*)tlv.data.constData());
							break;
						case TLV_EXTENSION_DATA:
							{
								CMemReadStream stmExt(tlv.data);
								BinaryReader rdExt(stmExt);
								UInt16 n, nFile;
								DWORD totalSize;
								rdExt >> n >> nFile >> totalSize;
								nFile = ntohs(nFile);
								totalSize = ntohl(totalSize);
								Blob name(0, tlv.data.Size-9);
								rdExt.Read(name.data(), name.Size);
								filename = String((const char*)name.constData());
							}
							break;
					}
				}
				if (ep.Port != 0 && !filename.IsEmpty()) {
					ptr<IcqFileMessage> msg = new IcqFileMessage;
					msg->Filename = filename;
					msg->From = IcqAnalyzer::s_curIcqAnalyzer->EnsureUser(IcqPacket::s_curPacket->m_our_uin);
					msg->To = IcqUser::GetByUin(Uin);
					msg->Finish();
					IcqAnalyzerClass::DccLruMap::value_type pp(ep, msg);
					IcqAnalyzerClass::I->DccEndpoints.insert(pp);
				}
			} else
				caps = caps;
		}
		break;
	case 4:
		{
			CMemReadStream bs(msgData5);
			DWORD uin;
			BYTE msgType, msgFlags;
			AsciizString az;
			BinaryReader(bs) >> uin >> msgType >> msgFlags >> az;
			OurUin = Convert::ToString(uin);
			switch (msgType) {
			case MTYPE_PLAIN:
				Text = az.ToString();
				break;
			case MTYPE_URL:
				if (const char *p = (const char *)az.m_blob.constData()) {
					for (size_t i=az.m_blob.Size; i--;)
						if (p[i] == 0xFE) {
							Text = String(p, i)+"\tURL: "+String(p+i+1, az.m_blob.Size-i-1);
							break;
						}
				}
				break;
			}
		}
		break;
	}
}


// Very first call in session

void IcqPacket::ProcessHello(const BinaryReader& rd) {
	UInt32 hello = rd.ReadUInt32();
	if (ntohl(hello) != 1)
		Throw(E_FAIL);
	vector<TLV> tlvs = TLV::ReadAll(rd);
	for (int k=0; k<tlvs.size(); ++k) {
		const TLV& tlv = tlvs[k];
		switch (tlv.type) {
		case TLV_SCREEN_NAME:
			m_our_uin = tlv.ToString();
			break;
		case TLV_PASSWORD:				 // Decrypt password during Login
			{					
				static const byte xora[] = { 0xf3, 0x26, 0x81, 0xc4, 0x39, 0x86, 0xdb, 0x92, 0x71, 0xa3, 0xb9, 0xe6, 0x53, 0x7a, 0x95, 0x7c };
				TLV wtlv = tlv;
				byte *data = wtlv.data.data();
				for (int i=tlv.data.Size; i--; )
					data[i] ^= xora[i % 16];
				m_our_pass = wtlv.ToString();
			}
			break;
		case TLV_AUTH_COOKIE:
			{
				CookieCache::iterator i = IcqAnalyzerClass::I->AuthCookies.find(tlv.data);
				if (i != IcqAnalyzerClass::I->AuthCookies.end())
					User = i->second.first;
			}
			break;;
		}
	}
}

void IcqPacket::ProcessAuthKey(const BinaryReader& rd) {
	UInt16 len = rd.ReadUInt16();
	m_icqAnalyzer.m_authKey.Size = len = ntohs(len);
	rd.Read(m_icqAnalyzer.m_authKey.data(), len);
	TRC(1, "Server AuthKey: " << m_icqAnalyzer.m_authKey);
}

void IcqPacket::ProcessLoginRequest(const BinaryReader& rd) {
	vector<TLV> tlvs = TLV::ReadAll(rd);
	for (int k=0; k<tlvs.size(); ++k) {
		const TLV& tlv = tlvs[k];
		switch (tlv.type) {
		case TLV_MD5:
			{
				if (tlv.data.Size != 16)
					Throw(E_FAIL);
				TRC(1, "MD5: " << tlv.data);
//!!!				const byte *md5 = tlv.data.constData();
			}
			break;
		}
	}
}

// Redirect to other server after Hello

void IcqPacket::ProcessDisconnect(const BinaryReader& rd) {
	vector<TLV> tlvs = TLV::ReadAll(rd);
	for (int k=0; k<tlvs.size(); ++k) {
		const TLV& tlv = tlvs[k];
		switch (tlv.type) {
		case TLV_SCREEN_NAME:
			m_our_uin = tlv.ToString();
			break;
		case TLV_SERVER_ENDPOINT:
			IcqAnalyzerClass::I->LoginCookies.push_back(IPEndPoint(tlv.ToString()));
			break;
		case TLV_AUTH_COOKIE:
			IcqAnalyzerClass::I->AuthCookies.insert(CookieCache::value_type(tlv.data, IcqUser::GetByUin(m_our_uin)));
			break;
		}
	}
}

static LONG s_arServerSnac[] = {
	SRV_USER_ONLINE, SRV_USER_OFFLINE,
	SRV_CLIENT_ICBM, SRV_ONLINExINFO
};

static LONG s_arClientSnac[] = {
	CLI_SEND_ICBM
};

void IcqPacket::Parse(const ConstBuf& data, IcqAnalyzerStream *ias) {
	s_curPacket = this;

	CMemReadStream stm(data);
	BinaryReader rd(stm);
	Flap flap;
	rd.ReadStruct(flap);
	
	TRC(2, flap);
	
	switch (flap.chan) {
	case 1:
		if (flap.Length > 4) {
			ProcessHello(rd);
			Type = ICQ_INIT;
		}
		break;
	case 2:
		Type = ICQ_SNAC;
		rd.ReadStruct(m_snac);
		
		TRC(1, m_snac);
		
		SnacType = ESnacType((m_snac.Family<<16)|m_snac.Subtype);
		for (int i=0; i<_countof(s_arServerSnac); i++) {
			if (s_arServerSnac[i] == SnacType) {
				ias->EnsureIncoming();
				break;
			}
		}
		for (int i=0; i<_countof(s_arClientSnac); i++) {
			if (s_arClientSnac[i] == SnacType) {
				ias->EnsureOutgoing();
				break;
			}
		}
		if (m_snac.flags & 0x8000) {
			WORD lenSomeData = rd.ReadUInt16();
			rd.Read(0, ntohs(lenSomeData));
		}
		switch (SnacType) {
		case SRV_ONLINExINFO:
			ias->m_analyzer->m_user = IcqUser::GetByUin(ReadUin(rd));
			break;
		case CLI_SEND_ICBM:
			TRC(1, "From client");
			rd >> icbm;
			break;
		case SRV_CLIENT_ICBM:
			TRC(1, "To client");
			icbm.m_bFromServer = true;
			rd >> icbm;
			break;
		case CLI_ICBM_SENDxACK:
			{
				BinaryReader rdstm(stm);
				icbm.ReadBase(rdstm);
				WORD reason = rd.ReadUInt16();
				switch (ntohs(reason)) {
				case 3:
					switch (icbm.Header.msg_channel) {
					case 2:
						icbm.ReadExtensionData(rdstm);
						break;
					}
					break;
				}
			}
			break;
		case CLI_META_REQ:
			ProcessMetaReq(rd);
			break;
		case SRV_META_REPLY:
			ProcessMetaReply(rd);
			break;
			
		case SNAC_SIGNON_AUTH_KEY:
			ProcessAuthKey(rd);
			break;
		case SNAC_SIGNON_LOGIN_REQUEST:
			ProcessLoginRequest(rd);
			break;
		}
		break;
	case 4:
		if (flap.Length > 0) {
			ProcessDisconnect(rd);
			Type = ICQ_DISCONNECT;
		}
		break;
	}
}

void IcqAnalyzerStream::ParsePacket(const ConstBuf& mb) {
	IcqAnalyzer& ia = *(IcqAnalyzer*)m_analyzer;

	IcqAnalyzer::s_curIcqAnalyzer = &ia;


#ifdef _X_DEBUG //!!!D
	if (mb.m_len == 0x1A6)
		ia.m_ci->DstEndPoint.Port = ia.m_ci->DstEndPoint.Port;
#endif

#ifdef _DEBUG//!!!D
	static int s_i;
	s_i++;
	if (s_i == 502)
		s_i = s_i;
#endif

	IcqPacket packet(ia);
	try {
		packet.Parse(mb, this);
	} catch (RCExc) {
	}

	switch (packet.Type) {
	case ICQ_INIT:
		if (packet.User)
			ia.m_user = packet.User;
		else
			ia.m_user = IcqUser::GetByUin(packet.m_our_uin, ia.GetSrcAddress()); //!!!, m_info.server_ip);
		if (!packet.m_our_uin.IsEmpty())
			ia.m_user->SetPassword(packet.m_our_pass);
		break;
	case ICQ_SNAC:
		switch (packet.SnacType) {
		case CLI_SEND_ICBM:
		case SRV_CLIENT_ICBM:
		case CLI_ICBM_SENDxACK:
			if (!packet.icbm.Text.IsEmpty()) {
				MessageBlock msgBlock;
				msgBlock.Timestamp = packet.icbm.Header.timestamp;
				msgBlock.Cookie = packet.icbm.Header.msgid;
				msgBlock.Text = RtfToText(packet.icbm.Text);
				if (IcqAnalyzerClass::I->LastMessages.insert(msgBlock).second) {
					ia.EnsureUser(packet.m_our_uin);
					ptr<IcqMessage> msg = new IcqMessage;
					msg->Text = msgBlock.Text;
					ptr<User> u = IcqUser::GetByUin(packet.icbm.Uin);
					if (packet.SnacType == SRV_CLIENT_ICBM) { //!!!
						msg->From = u;
						msg->To = ia.m_user;
					} else {
						msg->From = ia.m_user;
						msg->To = u;
					}
					msg->Finish();
				}
			}
			break;
		}
		break;
	}
}

void IcqAnalyzerStream::Process(const ConstBuf& data) {
//!!!	TRC(0, data.m_len << "\tStage: " << m_rstage << "\tState: " << m_state);

	switch (m_rstage) {								// Icq-packets are separated by '*'. Find first '*', then second (m_rstage=2)
	case 0:
		if (m_analyzer->m_ci) {
			TRC(3, "Src Port: " << m_analyzer->m_ci->SrcEndPoint.Port);
			m_bWasSYN = m_analyzer->m_ci->GetWasSYN();
		}
		if (data.P[0] != '*') {
			if (m_bWasSYN)
				m_analyzer->Delete();
			else {
				m_matchPattern = ConstBuf("*", 1);
				m_state = ASTATE_NEED_MATCH;
				m_rstage = 1;
			}
			break;
		}
	case 1:
		m_state = ASTATE_NEED_MORE;
		m_wanted = sizeof(Flap);
		if (data.Size >= m_wanted) {
			const Flap& flap = *(const Flap*)data.P;
			m_wanted = sizeof(Flap)+flap.Length;
			if (((IcqAnalyzer*)m_analyzer)->m_bRecognized)
				m_rstage = 3;
			else {
				m_wanted++;
				m_rstage = 2;
			}
		}
		break;
	case 2:
		{
			const Flap& flap = *(const Flap*)data.P;
			if (data.P[m_wanted-1] == '*') {
				m_rstage = 3;
				if (m_bWasSYN)
					MemorizeServer();
				m_analyzer->Capture();
			}
			else if (m_bWasSYN)
				m_analyzer->Delete();
			else if (m_offset > MAX_RECOGNIZE)
				m_analyzer->Delete();
			else {
				m_rstage = 1;
				m_processed = 1;
				m_matchPattern = ConstBuf("*", 1);
				m_state = ASTATE_NEED_MATCH;
			}
		}
		break;
	}
	if (m_rstage == 3) { // Recognized
		const Flap& flap = *(const Flap*)data.P;
		if (flap.start != '*') {
			m_analyzer->Delete();
			return;
		}
		if (data.Size < (m_wanted=sizeof(Flap)+flap.Length))
			return;
		ParsePacket(ConstBuf(data.P, m_processed=exchange(m_wanted, sizeof(Flap))));
	}
}

IcqAnalyzer::IcqAnalyzer() {
	SetOutStm(&m_outStm);
	SetInStm(&m_inStm);
}

IcqAnalyzerClass *IcqAnalyzerClass::I;

void IcqAnalyzerStream::MemorizeServer() {
	if (m_analyzer->m_ci && m_analyzer->m_ci->GetWasSYN())
		IcqAnalyzerClass::I->IcqServers.insert(m_analyzer->m_ci->DstEndPoint.Address);
}

static IPEndPoint s_epIcqServer;

bool IcqAnalyzer::TryRecognize() {
	IcqAnalyzerClass *cl = IcqAnalyzerClass::I;
	bool bSrc = cl->IcqServers.find(m_ci->SrcEndPoint.Address) != cl->IcqServers.end(),
		   bDst = cl->IcqServers.find(m_ci->DstEndPoint.Address) != cl->IcqServers.end();
	if (bool r = bSrc || bDst) {
		if (!m_ci->GetWasSYN() && bSrc)
			m_ci->SwapStreams();
		return r;
	}
	for (list<IPEndPoint>::iterator i=cl->LoginCookies.begin(); i!=cl->LoginCookies.end(); ++i)
		if (*i == m_ci->DstEndPoint) {
			cl->LoginCookies.erase(i);
			return true;
		}
	if (m_ci->DstEndPoint.Port == 5191)
		return true;
	
	if (m_ci->DstEndPoint == s_epIcqServer) {
		m_bRecognized = true;
		return true;
	}
	return false;
}


void IcqP2pAnalyzerStream::ParsePacket(const ConstBuf& mb) {
	IcqP2pAnalyzer& pa = *(IcqP2pAnalyzer*)m_analyzer;

	TRC(1, "ICQ P2P Process packet: " << (DWORD)mb.Size);
	IcqP2pPacket packet;
	packet.Parse(mb);
	switch (packet.m_type) {
	case ICQ_P2P_INIT:
		pa.PeerUser = IcqUser::GetByUin(packet.m_our_uin, m_analyzer->m_ci->SrcEndPoint.Address);
		pa.User = IcqUser::GetByUin(packet.m_peer_uin);
		break;
	case ICQ_P2P_MESSAGE:
		{
			String text = RtfToText(packet.m_text);
			ptr<IcqMessage> msg = new IcqMessage;
			msg->Text = text; //!!! s_reHtmlTags.Replace(text, "");
			msg->From = pa.User;
			msg->To = pa.PeerUser;
			msg->Finish();
		}
		break;
	}
}


IcqP2pAnalyzer::IcqP2pAnalyzer() {
	SetOutStm(&m_outStm);
	SetInStm(&m_inStm);
}

bool IcqP2pAnalyzer::TryRecognize() {
	if (!m_ci->GetWasSYN())
		Delete();
	else {
		IcqAnalyzerClass::DccLruMap::iterator i = IcqAnalyzerClass::I->DccEndpoints.find(m_ci->DstEndPoint);
		if (i != IcqAnalyzerClass::I->DccEndpoints.end()) {
			FileMessage = i->second.first;
			IcqAnalyzerClass::I->DccEndpoints.erase(i);
			Capture();
			return true;
		}		
	}
	return false;
}

class IcqP2pAnalyzerClass : public AnalyzerClass<IcqP2pAnalyzer> {
public:
	IcqP2pAnalyzerClass() {
		Priority = 10;
		Create("IcqP2p");
	}
};

/*!!!O
static String s_sIcqRequest = "http://web.icq.com/wwp?Uin=";
static Regex s_reIcqRes("color=\"#245892\" size=\"-2\">\\(([^<]+?)\\)</font>");
static String s_sIcqRequest = "http://www.icq.com/people/full_details_show.php?uin=";
 static Regex s_reIcqRes("flnm\">Nickname</div>\\s+<div class=\"udu-flvl\">(?<Nick>[^<]*)<");
*/

static String s_sIcqRequest = "http://www.icq.com/people/";
static wregex s_reIcqRes0(String("class=\"l\">Nickname</label>[^>]+>([^<]+)<")),
			s_reIcqRes1(String("(?:id=\"shortprofile\"[^/]+<div class=\"info_value[^>]+>([^<]+)<)")),		// nick - 1
             s_reIcqRes2(String("(?:h5-2-new)[^>]+>([^<]+)<"));		// Username - 1

class NoKeepAliveWebClient : public WebClient {
	typedef WebClient base;
protected:
	void OnHttpWebRequest(HttpWebRequest& req) {
		base::OnHttpWebRequest(req);
		req.KeepAlive = false;
	}
};


extern "C" {
	class CIcqMessageAnalyzerClass : public CMessageAnalyzerClass {

#if UCFG_SNIF_USE_TOR
		ptr<TorProxy> m_tor;
#endif
		ptr<User> QueryICQ(RCString uin) {
			TRC(1, "* QueryICQ: Going to resolve uin " << uin);

			static int s_i;
			bool bChangeProxyChain = !(++s_i % 10);

			Encoding::SetThreadIgnoreIncorrectChars(true);
			NoKeepAliveWebClient wc;
#if UCFG_SNIF_USE_TOR

#	ifdef X_DEBUG//!!!D
			if (!m_tor)
				m_tor = TorProxy::GetSingleton(true);
#	endif
			if (m_tor)
				wc.Proxy = m_tor;
#endif
			String content = wc.DownloadString(s_sIcqRequest+uin);
#ifdef X_DEBUG//!!!D
			ofstream ofs("c:\\tmp\\cont");
			Blob blob = Encoding::UTF8.GetBytes(content);
			ofs.write(blob.constData(), blob.Size);
			ofs.close();
#endif
        	String nick;
			Smatch m;
        	if (regex_search(content, m, s_reIcqRes0))
        		nick = m[1];
        	else if (regex_search(content, m, s_reIcqRes1))
        		nick = m[1];
        	else if (regex_search(content, m, s_reIcqRes2))
        		nick = m[1];
        	else
        		nick = nullptr;
			if (!nick.IsEmpty())
				nick = nick.Trim();
        	if (nick == uin)
        		nick = nullptr;
			else if (!!nick && nick.Find("Error Page") != -1) {
				nick = nullptr;
				bChangeProxyChain = true;
#if UCFG_SNIF_USE_TOR
				if (!m_tor) {
					m_tor = TorProxy::GetSingleton(true);
					return nullptr;
				}
#endif
			}
#if UCFG_SNIF_USE_TOR
			if (bChangeProxyChain && m_tor)
				m_tor->ChangeProxyChain();
#endif

			if (!!nick) {
				TRC(1, "ICQ RESOLVED: " << uin << ": " << nick);
				ptr<User> user = new User;
				user->Nick = nick;
				return user;			
			} else {
				TRC(1, "* UNMATCHED:" << content);
				return nullptr;
			}
		}

		bool Execute() override {
			if (s_epIcqServer.Port == 0) {
#ifdef _WIN32
				CUsingSockets usingSockets;
#endif
				try {
					DBG_LOCAL_IGNORE_NAME(HRESULT_FROM_WIN32(WSAHOST_NOT_FOUND), ignWSAHOST_NOT_FOUND);
					DBG_LOCAL_IGNORE_NAME(HRESULT_FROM_WIN32(WSANO_DATA), ignWSANO_DATA);

					s_epIcqServer = IPEndPoint(htonl(IPAddress::Parse("login.icq.com").GetIP()), 5190);
				} catch (RCExc) {
				}
			}
			if (!ConnectionManager::s_bEnableWebActivity)
				return false;
			String uin;
			EXT_LOCK (IcqAnalyzerClass::s_cs) {
				if (!IcqAnalyzerClass::I || IcqAnalyzerClass::I->m_qQuery.empty())
					return false;
				uin = IcqAnalyzerClass::I->m_qQuery.front();
			}
			ptr<User> user;
			try {
				user = QueryICQ(uin);
			} catch (RCExc) {
				TRC(1, "! ICQ Resolver exception.");
	//!!!      cerr << AfxProcessError(hr) << endl;
			}
			EXT_LOCK (IcqAnalyzerClass::s_cs) {
				if (IcqAnalyzerClass::I) {
					if (user)
						IcqAnalyzerClass::I->m_arResolved.push_back(make_pair(uin, user));
					if (!IcqAnalyzerClass::I->m_qQuery.empty())
						IcqAnalyzerClass::I->m_qQuery.pop_front();
				}
			}
			return true;
		}

		void Finalize() {
#if UCFG_SNIF_USE_TOR
			m_tor = nullptr;
#endif
		}
	public:
		CIcqMessageAnalyzerClass()
			:	CMessageAnalyzerClass("ICQ")
		{
		}

		ptr<User> CreateUser() { return new IcqUser; }

		CMessageAnalyzer *CreateObject() {
			Users.Load();
			return new CMessageAnalyzer(new IcqAnalyzerClass, new IcqP2pAnalyzerClass);
		}
	} g_icqMessageAnalyzerClass;
}

void IcqAnalyzerClass::InThreadExecute() {
	bool bSave = false; {
		EXT_LOCK (IcqAnalyzerClass::s_cs) {
			for (size_t i=m_arResolved.size(); i--;) {
				bSave = true;
				ptr<User> u = IcqUser::GetByUin(m_arResolved[i].first);
				ptr<User> userdata = m_arResolved[i].second;
				u->Nick = userdata->Nick;
			}
			m_arResolved.clear();
		}
	}
	if (bSave)
		g_icqMessageAnalyzerClass.Users.Save();
}

/*!!!
void IcqUser::PostLoad()
{
	if (m_nick == "")
		g_icqMessageAnalyzerClass.AddICQQuery(m_id);
}*/

IcqMessage::IcqMessage() {
	m_analyzerClass = &g_icqMessageAnalyzerClass;
}

IcqUser::IcqUser(RCString uin, const IPAddress& clientIP) {
	g_icqMessageAnalyzerClass.Users.AddInitial(this);
	Uid = uin;
	if (!clientIP.IsEmpty())
		ClientAddress = clientIP;
}

IcqUser *IcqUser::GetByUin(RCString uin, const IPAddress& clientIP) {
	TRC(1, "ICQ::GetByUIN: " << uin << " " << clientIP);

	IcqUser *u = static_cast<IcqUser*>(g_icqMessageAnalyzerClass.Users.FindUserByID(uin, clientIP));
	if (!u) {
		u = new IcqUser(uin, clientIP);
		g_icqMessageAnalyzerClass.Users.Save();
	}
	if (!uin.IsEmpty() && u->get_Nick().IsEmpty() && g_opt_ResolveEnabled)
		IcqAnalyzerClass::I->AddICQQuery(uin);
	return u;
}

ptr<User> IcqUser::FindByPhone(RCString phone) {
	ptr<User> u = g_icqMessageAnalyzerClass.Users.FindUserByPhone(phone);
	if (!u)
		(u = new IcqUser)->MobilePhone = phone;
	return u;
}

ptr<User, Interlocked> IcqAnalyzer::EnsureUser(RCString uin) {
	if (m_user) {
		if (!uin.IsEmpty())
			m_user = IcqUser::GetByUin(uin);
	} else
		m_user = IcqUser::GetByUin(uin, GetSrcAddress());
	return m_user;
}

// Wait first packet with data[3] == 0xFF
// After N bytes should be packet with data[3]==0x02
// Stream should be (SYN)
void IcqP2pAnalyzerStream::Process(const ConstBuf& data) {
	IcqP2pAnalyzer& an = *(IcqP2pAnalyzer*)m_analyzer;

	switch (m_rstage) {
	case 0:
		switch (UInt32 sig = Fast_ntohl(*(UInt32*)data.P)) {
		case 'OFT2':
		case 'OFT3':
			m_rstage = 10;
			m_wanted = 256;
			break;
		default:
			if (IsOut) {
				if (memcmp(data.P+2, "\xFF\x08\x00", 3)) {
					m_analyzer->Delete();
					return;
				} else
					m_analyzer->Capture();
			} else if (memcmp(data.P, "\x04\x00\x01\x00\x00", 5)) {
				m_analyzer->Delete();
				return;
			}
			m_rstage = 3;
		}
		break;
	
	case 10:		 // File Transfer
		if (!IsOut) {
#if UCFG_SNIF_PACKET_CAPTURE
			if (CTcpMan::s_bEnableLog && an.FileMessage && g_opt_SaveFiles) {
				String dir = Path::Combine(g_icqMessageAnalyzerClass.Dir, "files");
				Directory::CreateDirectory(dir);
				String fn = Path::Combine(dir, an.FileMessage->Filename);
				an.FileMessage->m_stm.Open(fn, FileMode::Create, FileAccess::Write);
			}
#endif
			m_processed = 256;
			m_wanted = 1;
			m_rstage = 11;
		} else {
			m_processed = data.Size;
		}
		break;
	case 11:
		if (an.FileMessage && an.FileMessage->m_stm.m_fstm)
			an.FileMessage->m_stm.WriteBuffer(data.P, data.Size);
		m_processed = data.Size;
		break;
	}
	if (m_rstage == 3) {
		size_t size = MAKEWORD(data.P[0], data.P[1]);
		m_wanted = size+2;
		if (data.Size >= m_wanted) {
			ParsePacket(ConstBuf(data.P+2, size));
			m_processed = exchange(m_wanted, 2);
		}
	}
}



} // Snif::


