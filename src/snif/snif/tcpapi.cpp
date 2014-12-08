/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#if UCFG_CRASH_DUMP
#	include <el/comp/crashdump.h>
#endif

#include <snif.h>

#if UCFG_SNIF_USE_PCAP
#	include "pcap-snif-eng.h"
#else
#	include <pcap-int.h>
#endif

#include "tcpapi.h"

#if UCFG_SNIF_ARPSPOOF
#	include "arpspoof.h"
#endif

#if UCFG_SNIF_WIFI
#	include "802_11.h"
#endif

#include "resource.h"

#pragma warning(disable: 4073)
#pragma init_seg(lib)


namespace Snif {


vector<CTcpAnalyzer*> CTcpAnalyzer::m_all;

CAppBase *g_wpcapApp;

int g_opt_LogLevel = 1;
bool g_opt_PrintAsDateTime = false;

#ifdef WIN32
CAppBase * __stdcall GetWpcapApp() {
	if (g_wpcapApp)
		return g_wpcapApp;
	return AfxGetCApp();
}

#if UCFG_SNIF_PACKET_CAPTURE
void _cdecl WpcapCloseAll() {
#if UCFG_SNIF_ARPSPOOF
	{
		EXT_LOCK (g_mtxSnif) {
			IArpSpoofer::IOwner = 0;
		}
	}
#endif
#if UCFG_SNIF_HOST_RESOLVE
	CHostResolver::IOwner = 0;
#endif
	g_trWpcap.StopChilds();
#if UCFG_SNIF_PROTECT_WPCAP_CLOSEALL
	try {
#endif
	ExPacketCloseAll();
#if UCFG_SNIF_PROTECT_WPCAP_CLOSEALL
	} catch (RCExc DBG_PARAM(e)) {
		TRC(0, e);
	}
#endif
}

AtExitRegistration s_atexitWpcap(&WpcapCloseAll);
#endif

/*!!!R
extern "C" __declspec(noreturn) void __cdecl ExitEx(int n)
{
	WpcapCloseAll();
	_exit(n);
}*/
#endif

//!!!CTcpMan g_tcpMan;


//!!!int *g_usesPlugins[] = { &forceEthernet, &forcePPP, &forceTokenRing, &forceIP, &forceIP6, &forceTCP };

void TcpConnection::Delete() {
	TRC(0, "TcpConnection::Delete: " << GetSrcEndPoint() << " -> " << GetDstEndPoint());

	m_an->m_mapConn.erase(m_iConn);
	//!!!  m_an.m_setConnection.erase(this);
}

IPEndPoint TcpConnection::GetSrcEndPoint() {
	return m_iConn->GetSrcEndPoint();
}

IPEndPoint TcpConnection::GetDstEndPoint() {
	return m_iConn->GetDstEndPoint();
}

CTcpAnalyzer::CTcpAnalyzer()
	:	m_bJustCreated(true)
{
	m_all.push_back(this);
}

CTcpAnalyzer::~CTcpAnalyzer() {
	Unbind();
}

void CTcpAnalyzer::Unbind() {
	Ext::Remove(m_all, this);
}


/*!!!
ptr<TcpConnection> CTcpAnalyzer::Find(ITcpConnection *conn)
{

for (CSetConnection::CIterator i(m_setConnection); i; i++)
if ((*i)->m_iConn == conn)
return *i;
return 0;
}*/

#if !UCFG_SNIF_PACKET_CAPTURE
bool CTcpMan::s_bEnableLog;
#endif

void CTcpMan::UpdatePos(ITcpConnection *conn) {
	tcppos_t posIn = numeric_limits<tcppos_t>::max(), posOut = posIn;
	for (size_t i=CTcpAnalyzer::m_all.size(); i--;) {
		if (TcpConnection *c = CTcpAnalyzer::m_all[i]->Find(conn)) {
			posIn = min(posIn, c->InStream.GetPos());
			posOut = min(posOut, c->OutStream.GetPos());
		}
	}
	conn->DiscardIn(DWORD(posIn-conn->GetInPos()));
	conn->DiscardOut(DWORD(posOut-conn->GetOutPos()));
}

void TcpStream::Skip(size_t bytes) {
	m_pos += bytes;
	m_conn.m_tcpMan->UpdatePos(m_conn.m_iConn);
}

ConstBuf TcpStream::GetData() {
	ConstBuf mb = m_bOut ? m_conn.m_iConn->GetOutData() : m_conn.m_iConn->GetInData();
	tcppos_t pos = m_bOut ? m_conn.m_iConn->GetOutPos() : m_conn.m_iConn->GetInPos();
	m_pos = max(m_pos, pos);//!!!
	int off = int(m_pos-pos);
	return ConstBuf(mb.P+off, mb.Size-off);
}

class TcpFlowPlugin : public ITcpFlowPlugin {
public:
	CTcpMan& m_tcpMan;

	TcpFlowPlugin(CTcpMan& tcpMan)
		:	m_tcpMan(tcpMan)
	{}

private:
	void CreatedConnection(ITcpConnection *conn) override {
		for (size_t i=CTcpAnalyzer::m_all.size(); i--;) {
			CTcpAnalyzer& an = *CTcpAnalyzer::m_all[i];
			an.m_bJustCreated = false;
			ptr<TcpConnection> c = an.CreateTcpConnectionObject(m_tcpMan,conn);
			an.CreatedConnection(an.m_mapConn[conn] = c);
		}
	}

	void CheckJustCreated(CTcpAnalyzer& an, ITcpConnection *conn) {
		if (an.m_bJustCreated) {
			ptr<TcpConnection> c = an.CreateTcpConnectionObject(m_tcpMan,conn);			
			an.CreatedConnection(an.m_mapConn[conn] = c);
			an.m_bJustCreated = false;
		}
	}

	void ClosedConnection(ITcpConnection *conn, int timeOut) override {
		TRC(3, "ClosedConnection: " << conn->GetSrcEndPoint() << " -> " << conn->GetDstEndPoint());

		for (size_t i=CTcpAnalyzer::m_all.size(); i--;) {
			CTcpAnalyzer& an = *CTcpAnalyzer::m_all[i];
			CTcpAnalyzer::CMapConn::iterator it = an.m_mapConn.find(conn);
			if (it != an.m_mapConn.end()) {
				an.ClosedConnection(it->second.get());
				an.m_mapConn.erase(it);
			}
		}
	}

	void UpdatedConnection(ITcpConnection *conn) override {
		TRC(3, conn->GetSrcEndPoint() << " -> " << conn->GetDstEndPoint());
		
		bool b = false;
		for (size_t i=CTcpAnalyzer::m_all.size(); i--;) {
			CTcpAnalyzer& an = *CTcpAnalyzer::m_all[i];
			CheckJustCreated(an,conn);
			if (TcpConnection *c = an.Find(conn)) {
				b = true;
				an.UpdatedConnection(c);
			}

		}
		if (!b)
			conn->Delete();
	}

	void FoundHole(ITcpConnection *conn) override {
		for (size_t i=CTcpAnalyzer::m_all.size(); i--;) {
			CTcpAnalyzer& an = *CTcpAnalyzer::m_all[i];
			if (TcpConnection *c = an.Find(conn))
				an.FoundHole(c);
		}
	}
};

CTcpMan::CTcpMan()
	:
#if UCFG_SNIF_PACKET_CAPTURE
	CProtoEng(false),
#endif
	m_tcpFlowPlugin(new TcpFlowPlugin(_self))
{
#if UCFG_SNIF_PACKET_CAPTURE
	GetTcpObj()->SubscribeFlow(m_tcpFlowPlugin);
	m_bEnabled = true;
#endif
}



int g_Cflag;
#ifdef WIN32
pcap_t g_pd;
#endif



#if UCFG_SNIF_CUI

void PrintAdapters(const CSnifEng& eng) {
	CSnifEng::CAdapters ar = eng.GetAdapters();
	for (int i=0; i<ar.size(); i++) {
		Adapter& ad = *ar[i];
		cout << i+1 << ". " << ad.m_desc.Name << "\t" << ad.m_desc.Description << endl;
	}
	cout << endl;
}


#if UCFG_SNIF_USE_PCAP

#ifndef SNIF_DUMP_INFO_DEFINED
struct dump_info {					//!!! second decl
	char	*WFileName;
	pcap_t	*pd;
	pcap_dumper_t *p;
};
#endif

struct dump_info dumpinfo;

#else

struct dump_info dumpinfo;

void __cdecl Wpcap_dump_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp) {
	pcap_dump(user, h, sp);
	pcap_dump_flush((pcap_dumper_t *)user);
}

void __cdecl Wpcap_dump_packet_and_trunc(u_char *user, const struct pcap_pkthdr *h, const u_char *sp) {
	struct dump_info *dump_info;
	static uint cnt = 2;
	char *name;

	dump_info = (struct dump_info *)user;

	/*
	* XXX - this won't prevent capture files from getting
	* larger than Cflag - the last packet written to the
	* file could put it over Cflag.
	*/
	if (ftell((FILE *)dump_info->p) > g_Cflag) {
		name = (char *) malloc(strlen(dump_info->WFileName) + 4);
		if (name == NULL)
			PcapThrow("dump_packet_and_trunc: malloc");
		strcpy(name, dump_info->WFileName);
		swebitoa(cnt, name + strlen(dump_info->WFileName));
		cnt++;
		pcap_dump_close(dump_info->p);
		dump_info->p = pcap_dump_open(dump_info->pd, name);
		free(name);
		if (dump_info->p == NULL)
			PcapThrow(pcap_geterr(&g_pd));
	}

	pcap_dump((u_char *)dump_info->p, h, sp);
	pcap_dump_flush(dump_info->p);
}
#endif

bool g_bArpSpoofingEnabled = true;

void CProtoEng::ParseCommandLine(int argc, char *argv[], bool bCreateArpSpoofer) {
	int Dflag = 0;
	vector<String> iargs;

	const char *infile = 0;
	int tCount = 0;
	for (int arg; (arg = getopt(argc, argv, m_options)) != EOF;) {
		switch (arg)
		{
#if UCFG_SNIF_ARPSPOOF
		case 'A':
			{
				if (String(optarg) == "no") {
					g_bArpSpoofingEnabled = false;
					bCreateArpSpoofer = false;
					break;
				}
				regex reIp("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|all)");
				cmatch m;
				if (regex_match(optarg, m, reIp)) {
					IArpSpoofer::Get();
					String s = m[1];
					if (s == "all") {
						cerr << "spoofing the whole network\n";
						IArpSpoofer::I->SetSpoofByDefault(true);
					} else
						IArpSpoofer::I->Spoof(IPAddress::Parse(s), true);
				} else {
					cerr << "unrecognized host format\n";
					Throw(0);
				}
			}
			break;
#endif
#if UCFG_WIN32
		case 'B':
			CUpgradeBase::I->AutoGetwork = true;
			break;
#endif
		case 'C':
			g_Cflag = atoi(optarg) * 1000000;
			if (g_Cflag < 0)
				PcapThrow("invalid file size");
			break;
		case 'D': Dflag++; break;
		case 'F':
			infile = optarg;
			break;
		case '?': 
			if (m_bAllowOtherOptons)
				break;
		case 'h':
			PrintUsage();
			Throw(0);
		case 'i': iargs.push_back(optarg); break;
#if UCFG_SNIF_WIFI
		case 'k':
			g_wifiKeys.push_back(WepKey(optarg));
			UpdateWifiKeys();
			break;
#endif
#if UCFG_CRASH_DUMP
		case 'q': CCrashDump::m_bQuiet = true;
			break;
#endif
		case 'r':
			if (!m_prov.get())
				m_prov.reset(new CFilesPacketProvider);
			((CFilesPacketProvider*)m_prov.get())->m_filenames.push_back(optarg);
			break;
		case 't':
			++tCount;
			break;
		case 'v':
			g_opt_LogLevel = atoi(optarg);
			break;
#if !UCFG_SNIF_USE_PCAP
		case 'w':
			dumpinfo.WFileName = optarg;
			break;
#endif
		default:
			if (!ProcessOption((char)arg,optarg)) {				//!!!
				cerr << "error: unrecognized switch \'" << (char)optopt << "\'" << endl;
				PrintUsage();
				Throw(1);
			}
		}
	}
	g_opt_PrintAsDateTime = tCount==4;
	if (Dflag) {
		if (iargs.empty())
			PrintAdapters(SnifEng());
#if UCFG_SNIF_REMOTE
		else {
			for (int i=0; i<iargs.size(); i++) {
				struct CNotifyWait : INotifyHook {
					CEvent m_ev;

					void OnNotifyHook() { m_ev.Set(); };
				} notifyWait;
				CRemoteSnifEng reng(iargs[i]);
				reng.SetNotifyHook(&notifyWait);

				Wait(SafeHandle::HandleAccess(notifyWait.m_ev));
				if (reng.m_exc) {
					try {
						rethrow_exception(reng.m_exc);
					} catch (RCExc ex) {
						cerr << ex.Message;
					}
				} else
					PrintAdapters(reng);
			}
		}
#endif
		Throw(0);
	}
	
	if (!m_prov.get() && SnifEng().GetAdapters().empty()) {
		cerr << "No adapters can be opened, probably you don't have permission" << endl;
	}
	if (!iargs.empty()) {
		CSnifEng::CAdapters ar = SnifEng().GetAdapters();
		for (int i=0; i<ar.size(); i++)
			ar[i]->Enabled = false;
		for (int i=0; i<iargs.size(); i++) {
			String device = iargs[i];
			const char *s = device;
#if UCFG_SNIF_REMOTE
			if (strstr(s,"rpcap:") == s)
				new RemoteAdapter(*(new CRemoteSnifEng),device);
			else
#endif
			{
				int n = atoi(device);
				if (n) {
					n--;
					if (n<0 || n >= ar.size())
						Throw(E_Sniffer_NoSuchAdapter);
				} else {
					for (int i=0; i<ar.size(); i++) {
						if (ar[i]->m_desc.Name == device) {
							n = i;
							goto LAB_FOUND;
						}
					}
					Throw(E_Sniffer_NoSuchAdapter);
				}
LAB_FOUND:
				m_nAdapter = n;
				ar[n]->Enabled = true;
			}
		}
	}

#if UCFG_SNIF_ARPSPOOF
	if (IArpSpoofer::I) {
		IArpSpoofer::I->m_bEnabled = true;
		IArpSpoofer::I->SetSpoofingEnabled(true);
	}
#endif
	String filter;
	if (infile) {
		Blob blob = File::ReadAllBytes(infile);
		filter = String((const char *)blob.constData(), blob.Size);
	} else {
		for (char **p = &argv[optind]; *p; p++)
			filter += *p+String(" ");
	}
	if (filter != "")
		try {
			SetUserFilter(filter);
		} catch (RCExc) {
			PrintUsage();
			Throw(1);
		}
#ifdef WIN32	//!!!
	if (dumpinfo.WFileName) {
		g_pd.snapshot = 65535;
		g_pd.tzoff = 0; //!!!
		g_pd.linktype = DLT_EN10MB; //!!!
#if !UCFG_SNIF_USE_PCAP		//!!!

		pcap_dumper_t *p = pcap_dump_open(&g_pd, dumpinfo.WFileName);
		if (p == NULL)
			PcapThrow(pcap_geterr(&g_pd));
		if (g_Cflag) {
			g_callback = Wpcap_dump_packet_and_trunc;
			dumpinfo.pd = &g_pd;
			dumpinfo.p = p;
			pcap_userdata = (u_char *)&dumpinfo;
		} else {
			g_callback = Wpcap_dump_packet;
			pcap_userdata = (u_char *)p;
		}
#endif
	}
#endif
	if (!m_prov.get() && bCreateArpSpoofer)
		SnifEng();
}
#endif


CThreadRef g_trWpcap(false);


ptr<SnifferPlugin> PluginClassBase::CreatePlugin(long layer, AnalyzerBinder *binder) {
	ptr<SnifferPlugin> p = (SnifferPlugin*)InstanceMap()[layer]->CreateObject();
	p->m_binder = binder;
	p->Bind();
	return p;
}

IMPLEMENT_DYNAMIC(CTcpConnection, Object)


void CTcpConnection::Delete() {
	TRC(0, m_source << " -> " << m_dest);

	m_bDeleted = true;
	m_in.Delete();
	m_out.Delete();
}

void CTcpConnection::Disconnect() {
	TRC(0, m_source << " -> " << m_dest);

	if (m_implConn)
		m_implConn->Disconnect();
	Delete();
}

mutex g_mtxSnif;

} // Snif::

