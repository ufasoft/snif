/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "standard-plugin.h"

#include "tcpapi.h"

#if UCFG_GUI
#	include "plugin-gui.h"
#endif

namespace Snif {

class TcpObj;
class TcpPacket;

class TcpWrap {
	typedef TcpWrap class_type;
public:
	tcphdr *m_tcp;

	WORD get_SrcPort() { return Fast_ntohs(m_tcp->th_sport); }
	DEFPROP_GET(WORD, SrcPort);

	WORD get_DstPort() { return Fast_ntohs(m_tcp->th_dport); }
	DEFPROP_GET(WORD, DstPort);

	DWORD get_Sequence() { return Fast_ntohl(m_tcp->th_seq); }
	DEFPROP_GET(DWORD, Sequence);

	DWORD get_Acknowledgement() { return Fast_ntohl(m_tcp->th_ack); }
	DEFPROP_GET(DWORD, Acknowledgement);

	BYTE get_Flags() { return m_tcp->th_flags; }
	DEFPROP_GET(BYTE, Flags);

	bool get_FIN() { return Flags & TH_FIN; }
	DEFPROP_GET(bool, FIN);

	bool get_SYN() { return Flags & TH_SYN; }
	DEFPROP_GET(bool, SYN);

	bool get_RST() { return Flags & TH_RST; }
	DEFPROP_GET(bool, RST);

	bool get_ACK() { return Flags & TH_ACK; }
	DEFPROP_GET(bool, ACK);

	inline TcpWrap(TcpPacket *iTP);
};

class TcpPacket : public PluginPacket {
	typedef TcpPacket class_type;

	DECLARE_DYNCREATE(TcpPacket)
protected:
	int GetLocalDataOffset() override { return TCPDataOffset*4; }
public:
#ifdef _DEBUG //!!!D
	~TcpPacket() {
		static int n = 0;
		n++;
	}
#endif

	TcpPacket *Clone() const {
		return new TcpPacket(_self);
	}

	String PortInfo(WORD port) {
		String s;
		if (servent *ent = getservbyport(htons(port),"tcp"))
			s = ent->s_name;
		else {
			switch (port) {
			case 135:
			case 139:
				s = "SMB";
				break;
			case 1080:
				s = "SOCKS";
				break;
			case 3128:
				s = "HTTP-Proxy";
				break;
			case 6667:
				s = "IRC";
				break;
			}
		}
		return s.IsEmpty()? "" : " "+s;
	}


	WORD get_SrcPort() { return GetHWord(0); }
	DEFPROP_GET(WORD, SrcPort);

	WORD get_DstPort() { return GetHWord(2); }
	DEFPROP_GET(WORD, DstPort);

	DWORD get_Sequence() { return GetHDWord(4); }
	DEFPROP_GET(DWORD, Sequence);

	DWORD get_Acknowledgement() { return GetHDWord(8); }
	DEFPROP_GET(DWORD, Acknowledgement);

	bool get_FIN() { return GetByte(13) & 1; }
	DEFPROP_GET(bool, FIN);

	bool get_SYN() { return GetByte(13) & 2; }
	DEFPROP_GET(bool, SYN);

	bool get_RST() { return GetByte(13) & 4; }
	DEFPROP_GET(bool, RST);

	bool get_PSH() { return GetByte(13) & 8; }
	DEFPROP_GET(bool, PSH);

	bool get_ACK() { return GetByte(13) & 16; }
	DEFPROP_GET(bool, ACK);

	bool get_URG() { return GetByte(13) & 32; }
	DEFPROP_GET(bool, URG);

	WORD get_Window() { return GetHWord(14); }
	DEFPROP_GET(WORD, Window);

	byte get_TCPDataOffset() { return GetByte(12) >> 4; }
	DEFPROP_GET(byte, TCPDataOffset);

#if UCFG_OLE
	void Info(CBag& bag) override {
		ptr<PluginPacket> iPP = StaticCast<PluginPacket>(m_iBase);
		iPP->Info(bag);
		CBag row;
		AddFieldInfo(row, "Source Port "+Convert::ToString(SrcPort)+PortInfo(SrcPort), 0, 2);
		AddFieldInfo(row, "Destination Port "+Convert::ToString(DstPort)+PortInfo(DstPort), 2, 2);
		AddFieldInfo(row, String("Sequence ")+Convert::ToString(Sequence), 4, 4);
		AddFieldInfo(row, String("Acknowledgement ")+Convert::ToString(Acknowledgement), 8, 4);
		AddFieldInfo(row, "Window "+Convert::ToString(Window), 14, 2);
		AddFieldInfo(row, "DataOffset "+Convert::ToString(TCPDataOffset), 12, 1);
		ostringstream os;
		os <<  "URG=" << int(URG)
			<< " ACK=" << int(ACK)
			<< " PSH=" << int(PSH)
			<< " RST=" << int(RST)
			<< " SYN=" << int(SYN)
			<< " FIN=" << int(FIN);
		AddFieldInfo(row, os.str(), 13, 1);
		long off = GetLocalDataOffset();
		AddFieldInfo(row, "Data", off, GetData().Size);
		bag.Add((CBag("TCP"), row));
	}
#endif
};

inline TcpWrap::TcpWrap(TcpPacket *iTP)
	:	m_tcp((tcphdr*)iTP->m_iBase->GetData().P)
{}


IMPLEMENT_DYNCREATE(TcpPacket, PluginPacket)



#ifdef _DEBUG //!!!D
DateTime g_dt;
int g_nAborted;
#endif

class CConnectionCloser {
public:
	CBool m_bValid;
	ptr<CTcpConnection> TcpConnection;

	CConnectionCloser(CTcpConnection *conn = 0)
		:	TcpConnection(conn)
	{}

	~CConnectionCloser() {
		if (m_bValid) {
			if (!TcpConnection->m_bCorrectlyClosed) {
#ifdef _DEBUG
				g_nAborted++;
#endif
//				TRC(3,"~CConnectionCloser:\t Aborted:" << g_nAborted << " " << g_dt << " " << HostToStr(TcpConnection->GetSrcIP()) << ":" << TcpConnection->GetSrcPort() << " > " << HostToStr(TcpConnection->GetDstIP()) << ":" << TcpConnection->GetDstPort());
			}
			TcpConnection->CloseEx();
		}
	}
};

class CResetedConn {
public:
	IPEndPoint m_ipPort;
	DWORD m_seq,
		m_otherSeq;
};

typedef LruMap<CConnID, CResetedConn> ResetedConnections;

class TcpObj : public ITcpPlugin, IIcmpHook {
	typedef TcpObj class_type;

	void OnReceivedIcmp(IcmpPacket *icmp) override {
		Buf mb = icmp->GetData();
		switch (icmp->Type) {
		case ICMP_REDIRECT: //!!! for efficiency against scanning
		case ICMP_UNREACH:
			if (mb.Size >= 4+sizeof(ip)+8) {
				ip *iph = (ip*)(mb.P+4);
				if (iph->ip_v == 4 && iph->ip_hl == 5 &&  iph->ip_p == IPPROTO_TCP) {
					tcphdr *tcp = (tcphdr*)(mb.P+4+sizeof(ip));
					CConnID connID(IPEndPoint(iph->ip_src.s_addr, ntohs(tcp->th_sport)),
								   IPEndPoint(iph->ip_dst.s_addr, ntohs(tcp->th_dport)));
					m_connections.erase(connID);
				}
			}
			break;
		}
	}
public:
	vector<ptr<ITcpFlowPlugin> > m_arFlowSubscribers;

	ResetedConnections m_reseted;

	class CConnections : public LruMap<CConnID, CConnectionCloser> {
		typedef LruMap<CConnID, CConnectionCloser> base;
	public:
		CConnections()
			:	base(TCP_DEFAULT_MAX_CONNECTIONS)
		{}

		CTcpConnection *GetConnection(const CConnID& connID, TcpObj *pPlugin) {
			iterator it = find(connID);
			if (it == end()) {
//				TRC(3, g_dt.ToString(Microseconds()) << " ESTABLISH: " << connID);

				pair<iterator,bool> ii = insert(value_type(connID, CConnectionCloser()));
				ASSERT(ii.second);

				ii.first->second.first.TcpConnection = new CTcpConnection(pPlugin);
				ii.first->second.first.m_bValid = true;
				it = ii.first;
			}
			return it->second.first.TcpConnection;
		}

		void Remove(CTcpConnection *conn) {
			erase(conn->GetConnID());
			//!!!      erase(remove(begin(),end(),conn),end());
		}
	} m_connections;
protected:
	bool CheckConditions(PluginPacket *iPacket) override {
		if (SnifferPlugin::CheckConditions(iPacket))
			return true;
#if UCFG_SNIF_USE_ODDB
		ptr<TcpPacket> iUP = static_cast<TcpPacket*>(iPacket);
		WORD src = iUP->SrcPort, dst = iUP->DstPort;
		CVariantIterator vi(m_obCond.GetProperty("Ports"));
		for (COleVariant v; vi.Next(v);) {
			WORD port = (WORD)Convert::ToInt32(v);
			if (src == port || dst == port)
				return true;
		}
#endif
		return false;
	}

#if UCFG_SNIF_USE_ODDB
	void DefinePluginClasses(COdClass& clCond) {
		clCond.CreateField("Ports","word []");
		COdDatabase db = clCond.Database;
		COdClass cl = db.Classes["BasePacket"];      
		cl = db.CreateClass("TcpConnection", cl);
		cl.CreateField("Timestamp", "currency");
		cl.CreateField("SourceIP", "dword");
		cl.CreateField("DestIP", "dword");
		cl.CreateField("SourcePort", "word");
		cl.CreateField("DestPort", "word");
		cl.CreateField("In", "binary");
		cl.CreateField("Out", "binary");
		cl.CreateField("InTimes", "currency []");
		cl.CreateField("OutTimes", "currency []");
		cl = db.Classes[m_name];
		cl.CreateField("Connections", "TcpConnection *[]");
		clCond.CreateField("ConcatStreams", "byte");
	}

	void UpgradePluginClasses(COdClass& clCond) override {
	}
#endif


	void ProcessPacket(PluginPacket *iPacket) override {
//		DBG_LOCAL_IGNORE(E_Sniffer_BadPacketFormat); //!!!

		TcpPacket *iTP = static_cast<TcpPacket*>(iPacket);
#ifdef _DEBUG//!!!D
		g_dt = iTP->GetRootPacket()->TimeStamp;
		//	TRC(1,"TCP Packet: " << g_dt.ToString(Microseconds()));
#endif
		IpPacket *iIPP = static_cast<IpPacket*>(iPacket->m_iBase.get());
//!!!R		IpWrap ipw(iIPP);
		TcpWrap tcp(iTP);

		ConstBuf mbSrcAddr = iIPP->GetSrcAddr(),
					mbDstAddr = iIPP->GetDstAddr();

		if (g_opt_LogLevel >= 2) {
			Buf mb = iIPP->GetData();

			UInt16 sum = CalculateWordSum(mbSrcAddr, CalculateWordSum(mbDstAddr));

			struct SHdr {
				UInt16 len;
				byte zero, proto;
			} hdr = { (UInt16)htons(UInt16(mb.Size)), 0, (byte)iIPP->GetProto() };

//!!!R			CTcpPseudoHeader phdr(ipw.m_ip->ip_src.s_addr, ipw.m_ip->ip_dst.s_addr, ipw.m_ip->ip_p, htons(short(mb.m_len)));
//!!!R			if (CalculateWordSum(mb, CalculateWordSum(ConstBuf((BYTE*)&phdr, sizeof phdr)), true)) {
			if (CalculateWordSum(ConstBuf(&hdr, sizeof hdr), sum, true)) {
				//!!! Here need SMART verifying vith delayed packets, beacuse HW cksum calculating
				TRC(1, "Bad TCP Checksum from " << IPAddress(mbSrcAddr));
				Throw(E_Sniffer_BadChecksum);
			}
		}
		SnifferPlugin::ProcessPacket(iPacket);
#if UCFG_SNIF_USE_ODDB
		if (m_obCond && !Convert::ToInt32(m_obCond.GetProperty("ConcatStreams")))
			return;
#endif
		if (bool bFirstSyn = tcp.SYN && !tcp.ACK && !iTP->GetData().Size)  // to prevent SYN-flooding
			return;
		IPEndPoint source(IPAddress(mbSrcAddr), tcp.SrcPort),
			dest(IPAddress(mbDstAddr), tcp.DstPort);

#ifdef _X_DEBUG //!!!D
		if (source.m_port == 1312 && dest.m_port == 80 || dest.m_port == 1312 && source.m_port == 80)
		{
			ILP_SnifferPacket iSP = iTP->GetRootPacket();
			TRC(1, "MyPacket: " << g_dt.ToString(Microseconds()) << "\tOrder: " << int(iSP->m_nOrder));			
			source = source;
		}
#endif

		CTcpConnection *c;
		CConnID connID(source,dest);
		CConnections::iterator i = m_connections.find(connID);
		if (i != m_connections.end())
			c = i->second.first.TcpConnection;
		else {
			ResetedConnections::iterator j = m_reseted.find(connID);
			if (j != m_reseted.end()) {
				const CResetedConn& rc = j->second.first;
				DWORD lastSeq = source==rc.m_ipPort ? rc.m_seq : rc.m_otherSeq;
				int diff = tcp.Sequence-lastSeq;
				if (abs(diff) < 64000) //!!!
					return;
			}
			c = m_connections.GetConnection(connID, this);
		}
		c->ProcessPacket(iTP);
#ifdef _X_DEBUG//!!!D
		{
			static int nPackets;
			if (!(nPackets++ & 0xFFF)) {
				ILP_SnifferPacket iSP = iPacket->GetRootPacket();
				TRC(0,iSP->m_timestamp << "\tTCP connection count:\t" << m_connections.size());//!!! << "\t" << CTcpConnection::s_nObjectCount);
			}
		}
#endif
	}
public:
#if UCFG_SNIF_USE_ODDB
	COdCollObjects m_collConnections;
#endif
#if UCFG_GUI
	ptr<DataSet> m_iConnectionDataSet;

	vector<String> GetDataSets() override {
		vector<String> vec;
		vec.push_back("Packets");
		vec.push_back("Connections");
		return vec;
	}
#endif

	TcpObj();
	~TcpObj();
protected:
	void Analyze(SnifferPacketBase *iPacket) override {
		TcpPacket packet;
		AnalyzeCreated(packet, iPacket);
	}

	void Bind() override {
		m_binder->m_mapIp[IPPROTO_TCP].insert(this);
	}

	void UnbindPlugin() override {
		m_binder->m_mapIp[IPPROTO_TCP].erase(this);
	}

	void SubscribeFlow(ITcpFlowPlugin *p) {
		m_arFlowSubscribers.push_back(p);
	}

#if UCFG_GUI
	void Connect(SnifferSite *pSite) override {
		SnifferPlugin::Connect(pSite);
		m_collConnections = m_obj.GetProperty("Connections");


		//!!!    OleCheck(m_iSite->GetPlugin(StringFromCLSID(CLSID_IP),&m_iBase));
		//    OleCheck(m_iBase->Subscribe(this,m_layer));
	}

	ptr<DataSet> GetDataSet(RCString name) override;
#endif

	void Disconnect() override {
		//!!!  OleCheck(m_iBase->Unsubscribe(this));
#if UCFG_SNIF_USE_ODDB
		m_collConnections.Release();
#endif
		SnifferPlugin::Disconnect();
	}

	void Clear() override {
		m_connections.clear();
		SnifferPlugin::Clear();
#if UCFG_SNIF_USE_ODDB
		m_collConnections.DeleteAll();
		CVariantIterator vi(m_obj.Database.Classes["TcpConnection"].Objects);
		for (COleVariant v; vi.Next(v);)
			COdObject(AsUnknown(v)).Delete();
#endif
	}

};

void CTcpStream::CheckFragments() {
	for (bool bLoop=true; exchange(bLoop, false);)
		for (CFrames::iterator i=m_frames.begin(); !bLoop && i!=m_frames.end();) {
			Int32 offset = i->m_seq-m_seq;
			if (offset <= 0) {
				Blob& data = i->m_data;
				Int32 size = offset+(int)data.Size;
				if (size > 0) {
					m_blob.Replace(m_blob.Size, 0, ConstBuf(data.constData()+data.Size-size, size));
					m_seq += size;
				}
				i = m_frames.erase(i);
				m_packetsAfterHole = 0;
				bLoop = true;
			} else
				++i;
		}
}

bool CTcpStream::CheckHoles(bool bAllHoles) {
	if (m_frames.empty() || m_packetsAfterHole<=TCP_MAX_PACKETS_AFTER_HOLE && !bAllHoles)
		return false;
	DWORD newSeq = m_frames[0].m_seq;
	for (CFrames::iterator i=m_frames.begin()+1; i!=m_frames.end(); ++i)
		if (Int32(i->m_seq-m_seq) < Int32(newSeq-m_seq))
			newSeq = i->m_seq;
	m_seq = newSeq;
	CheckFragments();
	if (!m_frames.empty()) {
		CFrames::iterator last = m_frames.end()-1;
		m_seq = last->m_seq;
		m_frames.erase(m_frames.begin(), last);
		CheckFragments();
		m_frames.clear();
	}
	m_packetsAfterHole = 0;
	return true;
}


void CTcpConnection::Save() {
#if UCFG_SNIF_USE_ODDB
	if (!m_ob) {
		m_ob = m_pPlugin->m_obj.Database.Classes["TcpConnection"].CreateObject();
		m_pPlugin->m_collConnections.Add(m_ob);
	}
	CY cy;
	cy.int64 = (__int64&)m_dt.ToFileTime();
	m_ob.SetProperty("Timestamp", COleCurrency(cy));
	m_ob.SetProperty("SourceIP", long(m_source.Address.GetIP()));
	m_ob.SetProperty("DestIP", long(m_dest.Address.GetIP()));
	m_ob.SetProperty("SourcePort", short(m_source.Port));
	m_ob.SetProperty("DestPort", short(m_dest.Port));
	m_ob.SetProperty("In", m_in.m_blob);
	m_ob.SetProperty("Out", m_out.m_blob);
#endif
}


CTcpConnection::SProcessResult CTcpConnection::ProcessStream(CTcpStream& stream, TcpPacket *iTP) {
	SProcessResult r;
	//!!!  m_nOrder = m_pPlugin->m_connections.m_nCurOrder++;

	TcpWrap tcp(iTP);

	DWORD seq = tcp.Sequence;
	bool bSYN = tcp.SYN;
	if (bSYN) {
		m_bWasSYN = true;
		stream.m_bSeqInited = false;
	}
	if (!stream.m_bSeqInited) {
		stream.m_bSeqInited = true;
		stream.m_seq = (seq+=bSYN);
	}
	ConstBuf mb = iTP->GetData();
	if (!m_bDeleted) {
		if (mb.Size && Int32(seq+mb.Size-stream.m_seq)>0) {
			stream.m_frames.push_back(CSeqData(seq, mb));
			size_t prevSize = stream.m_blob.Size;
			stream.CheckFragments();
			r.m_bUpdated = stream.m_blob.Size != prevSize;
			if (!stream.m_frames.empty())
				stream.m_packetsAfterHole++;
		}
	}
	CTcpStream& otherStream = m_arStm[stream.IsOut];
	if (tcp.FIN) {
		stream.m_bFIN = true;
		stream.m_finSeq = seq+mb.Size+1;
		//!!!		if (otherStream.m_bClosed)
		//!!!			stream.m_bClosed = true;
	}
	if (tcp.ACK) {
		DWORD ackSeq = tcp.Acknowledgement;
		if (ackSeq == otherStream.m_seq)
			otherStream.m_packetsAfterHole = 0;
		if (otherStream.m_bFIN && otherStream.m_finSeq==ackSeq)
			otherStream.m_bClosed = true;
	}
	//!!!	if (rst)
	//		stream.m_bClosed = true;
	return r;
}

void CTcpConnection::UpdatedConnection() {
	for (int i=0; i<m_pPlugin->m_arFlowSubscribers.size(); i++)
		m_pPlugin->m_arFlowSubscribers[i]->UpdatedConnection(this);
}

void CTcpConnection::FoundHole() {
//	TRC(1, g_dt.ToString(Microseconds()) << "  Hole found! " << m_source << " -> " << m_dest);

	for (int i=0; i<m_pPlugin->m_arFlowSubscribers.size(); i++)
		m_pPlugin->m_arFlowSubscribers[i]->FoundHole(this);
}

void CTcpConnection::ProcessPacket(TcpPacket *iTP) {
	IpPacket *iIPP = static_cast<IpPacket*>(iTP->m_iBase.get());
//!!!R	IpWrap ipw(iIPP);
	IPEndPoint source(IPAddress(iIPP->GetSrcAddr()), iTP->SrcPort);
	
	if (m_source.Address.IsEmpty()) {
		m_source = source;
		m_dest = IPEndPoint(IPAddress(iIPP->GetDstAddr()), iTP->DstPort);
		if (iTP->SYN && iTP->ACK) {
			swap(m_source, m_dest);
			m_out.m_bSeqInited = true;
			m_out.m_seq = iTP->Acknowledgement;
		}
		m_dt = iTP->GetRootPacket()->TimeStamp;

		for (int i=0; i<m_pPlugin->m_arFlowSubscribers.size(); i++) {
			try {
				m_pPlugin->m_arFlowSubscribers[i]->CreatedConnection(this);
			} catch (RCExc) {
			} 
		}
	}

	TRC(3, m_source << " -> " << m_dest);

	bool bOut = m_source == source;
	CTcpStream& stream = m_arStm[1-bOut];
	SProcessResult pr = ProcessStream(stream, iTP);
#if UCFG_SNIF_USE_ODDB
	if (m_pPlugin->m_obCond && Convert::ToBoolean(m_pPlugin->m_obCond.GetProperty("Save")))
		Save();
#endif
	if (!m_bDeleted) {
		if (pr.m_bUpdated)
			UpdatedConnection();
		if (stream.CheckHoles())
			FoundHole();
	}

	/*!!!				try
	{
	m_pPlugin->m_arFlowSubscribers[i]->UpdatedConnection(this);
	}
	catch (RCExc)
	{}*/
	bool rst = iTP->RST;
#ifdef _DEBUG
	if (rst) {
		TRC(3, "CTcpConnection::ProcessPacket  RST in " << m_source);
	}
#endif

	if (rst || m_out.m_bClosed && m_in.m_bClosed) {
#ifdef _X_DEBUG
		if (m_source.m_port == 1312)
			m_source = m_source;

#endif

		//!!!		if (rst)
		ResetedConnections::iterator i = m_pPlugin->m_reseted.insert(ResetedConnections::value_type(CConnID(m_source,m_dest), CResetedConn())).first;
		CResetedConn& rc = i->second.first;
		rc.m_ipPort = m_source;
		rc.m_seq = m_out.m_seq;
		rc.m_otherSeq = m_in.m_seq;
		//		TRC(1,"Closing: " << g_dt << "." << g_dt.Millisecond);
		m_bCorrectlyClosed = true;
		m_pPlugin->m_connections.Remove(this);
	}
}

void MyBreak() {

}

void CTcpConnection::CloseEx() {
	TRC(3, "CTcpConnection::CloseEx   connectinCount=" << m_pPlugin->m_connections.size());
#ifdef X_DEBUG//!!!D
	if (m_source.Port == 49981)
		MyBreak();
#endif

	while (m_in.CheckHoles(true)) {
		FoundHole();
		UpdatedConnection();
	}
	while (m_out.CheckHoles(true)) {
		FoundHole();
		UpdatedConnection();
	}

	for (int i=0; i<m_pPlugin->m_arFlowSubscribers.size(); i++) {
		try {
			m_pPlugin->m_arFlowSubscribers[i]->ClosedConnection(this,0);//!!! timeout
		} catch (RCExc) {
		}
	}
	//!!!  m_pPlugin->m_connections.Remove(this);
}

#if UCFG_GUI

class CFormTCP : public CConditionsView {
	DECLARE_DYNCREATE(CFormTCP)
public:
	CFormTCP();

	//{{AFX_DATA(CFormUDP)
	enum { IDD = IDD_TCP };
	CListBox	m_lbxPorts;
	CButton m_cbConcat;
	//}}AFX_DATA

	//{{AFX_VIRTUAL(CFormTCP)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL
protected:

	//{{AFX_MSG(CFormTCP)
	afx_msg void OnAdd();
	afx_msg void OnEdit();
	afx_msg void OnDelete();
	afx_msg void OnClickConcat();
	//}}AFX_MSG
	void SavePorts();

	DECLARE_MESSAGE_MAP()
};

class ConnectionDataSet : public DataSet {
	TcpObj& m_plugin;
	//!!!CUnkPtr m_iOwner;
protected:
	ptr<DataSetNotify> m_iNotify;

	ptr<Object> GetItem(int idx);
	size_t GetCount();
	vector<String> GetFields();
	void SetNotify(DataSetNotify *iNotify);
public:
	ConnectionDataSet(TcpObj& plugin);
};

ConnectionDataSet::ConnectionDataSet(TcpObj& plugin)
	:	m_plugin(plugin)//!!!,
//!!!   m_iOwner((ITcpPlugin*)&plugin)
{
}

ptr<Object> ConnectionDataSet::GetItem(int idx) {
	ptr<CTcpConnection> c = new CTcpConnection;
	c->m_ob = m_plugin.m_collConnections.GetItem(idx);
	c->Load();
	return c;
}

size_t ConnectionDataSet::GetCount() {
	return m_plugin.m_collConnections.Count;
}

vector<String> ConnectionDataSet::GetFields() {
	vector<String> ar;
	ar.push_back("Timestamp");
	ar.push_back("SourceIP");
	ar.push_back("SourcePort");
	ar.push_back("DestIP");
	ar.push_back("DestPort");
	return ar;
}

void ConnectionDataSet::SetNotify(DataSetNotify *iNotify) {
	m_iNotify = iNotify;
}


CFormTCP::CFormTCP()
	:	CConditionsView(IDD)
{
	//{{AFX_DATA_INIT(CDialogTCP)
	//}}AFX_DATA_INIT
}

void CFormTCP::DoDataExchange(CDataExchange* pDX) {
	CConditionsView::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDialogTCP)
	DDX_Control(pDX, LBX_PORTS, m_lbxPorts);
	DDX_Control(pDX, CB_CONCAT, m_cbConcat);
	//}}AFX_DATA_MAP
	CVariantIterator vi(m_pPlugin->m_obCond.GetProperty("Ports"));
	for (COleVariant v; vi.Next(v);)
		m_lbxPorts.AddString(Convert::ToString(Convert::ToInt32(v)));
	m_cbConcat.Check = Convert::ToInt32(m_pPlugin->m_obCond.GetProperty("ConcatStreams"));
}

IMPLEMENT_DYNCREATE(CFormTCP, CConditionsView)

BEGIN_MESSAGE_MAP(CFormTCP, CConditionsView)
	ON_BN_CLICKED(ID_ADD, &CFormTCP::OnAdd)
	ON_BN_CLICKED(ID_EDIT, &CFormTCP::OnEdit)
	ON_BN_CLICKED(ID_DELETE, &CFormTCP::OnDelete)
	ON_BN_CLICKED(CB_CONCAT, &CFormTCP::OnClickConcat)
END_MESSAGE_MAP()

void CFormTCP::OnAdd() {
	String s;
	if (InputQuery("AddPort", "Enter port:", s)) {
		m_lbxPorts.AddString(s);
		SavePorts();
	}
}

void CFormTCP::OnEdit() {
	int i = m_lbxPorts.CurSel;
	String s = m_lbxPorts.GetText(i);
	if (InputQuery("AddPort","Enter port:", s)) {
		m_lbxPorts.DeleteString(i);
		m_lbxPorts.InsertString(i, s);
		SavePorts();
	}
}

void CFormTCP::OnDelete() {
	m_lbxPorts.DeleteString(m_lbxPorts.CurSel);
	SavePorts();	
}

void CFormTCP::SavePorts() {
	COdCollection coll = m_pPlugin->m_obCond.GetProperty("Ports");
	coll.DeleteAll();
	for (int i=0; i<m_lbxPorts.Count; i++) {
		WORD port = (WORD)atoi(m_lbxPorts.GetText(i));
		coll.Add(COleVariant(long(port)));
	}
}

void CFormTCP::OnClickConcat() {
	m_pPlugin->m_obCond.SetProperty("ConcatStreams",COleVariant((long)m_cbConcat.Check));
}

ptr<DataSet> TcpObj::GetDataSet(RCString name) {
	if (name == "Connections") {
		if (!m_iConnectionDataSet)
			m_iConnectionDataSet = new ConnectionDataSet(_self);
		return m_iConnectionDataSet;
	}
	return SnifferPlugin::GetDataSet(name);
}


#endif

//!!!CTcpPluginClass g_classTCP;

int forceTCP;

ptr<ITcpPlugin> CreateTCP() {
	return new TcpObj;
}

TcpObj::TcpObj() {
	STATIC_ASSERT(offsetof(class_type, m_arFlowSubscribers) < offsetof(class_type, m_connections));

	m_name = "TCP";
	m_layer = PROTO_TCP;
#if UCFG_GUI
	m_pViewClass = RUNTIME_CLASS(CFormTCP);
#endif
	m_pPacketClass = RUNTIME_CLASS(TcpPacket);
	(m_icmpObj = new IcmpObj)->m_subscriber += this;
}

TcpObj::~TcpObj() {
}


extern "C" { PluginClass<TcpObj,PROTO_TCP> g_tcpClass; }


} // Snif::

