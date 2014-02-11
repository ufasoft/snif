/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

//!!!#include <pcap.h>
//!!!#include <pcap-int.h>
#include "tcpapi.h"

#if UCFG_GUI
#	include <el/gui/dialogs.h>
#endif

//#include <af.h>
/*
 * BSD AF_ values.
 *
 * Unfortunately, the BSDs don't all use the same value for AF_INET6,
 * so, because we want to be able to read captures from all of the BSDs,
 * we check for all of them.
 */
#define BSD_AFNUM_INET		2
#define BSD_AFNUM_NS		6		/* XEROX NS protocols */
#define BSD_AFNUM_ISO		7
#define BSD_AFNUM_APPLETALK	16
#define BSD_AFNUM_IPX		23
#define BSD_AFNUM_INET6_BSD	24	/* OpenBSD (and probably NetBSD), BSD/OS */
#define BSD_AFNUM_INET6_FREEBSD	28
#define BSD_AFNUM_INET6_DARWIN	30


namespace Snif {

CFilePacketProvider::CFilePacketProvider(pcap_t *p)
	:	CPacketProvider(p)
	,	m_i(0)
{
	m_medium = DltToMedium(pcap_datalink(m_pd));
}

//!!!pcap_t	* __cdecl original_pcap_open_offline(const char *, char *); //!!!

CFilePacketProvider *CFilePacketProvider::FromFilename(RCString filename) {
	char errbuf[PCAP_ERRBUF_SIZE];
#if UCFG_SNIF_USE_PCAP
	if (pcap_t *p = pcap_open_offline(filename,errbuf))
#else
	if (pcap_t *p = original_pcap_open_offline(filename,errbuf))
#endif
		return new CFilePacketProvider(p);
	else if (File::Exists(filename)) {
#if UCFG_WIN32		//!!!?
		if (Path::GetExtension(filename).ToUpper() == ".NCF")
			return CreateCommViewPacketProvider(filename);
#endif
		FileStream stm(filename, FileMode::Open, FileAccess::Read);
		BinaryReader rd(stm);
		UInt32 dwMagic = rd.ReadUInt32();
		switch (dwMagic) {
#if UCFG_XML && UCFG_WIN32
		case MULTI_CHAR_4('R', 'T', 'S', 'S'):
		case MULTI_CHAR_4('G', 'M', 'B', 'U'):
			return CreateNetMonPacketProvider(filename);
		case MULTI_CHAR_3('X', 'C', 'P'):
			return CreateNetxrayPacketProvider(filename);
		case MULTI_CHAR_4('<', '?', 'x', 'm'):
			Thread::CurrentThread->InitCOM();
			return new CXmlPacketProvider(filename);
#endif
		default:
			Throw(E_EXT_InvalidFileHeader);
		}
	} else
		PcapThrow(errbuf);
}

void CFilesPacketProvider::BreakLoop() { 
	m_bBreak = true;
	EXT_LOCK (m_csProv) {
		if (m_prov.get())
			m_prov->BreakLoop();
	}
}

ILP_SnifferPacket CFilesPacketProvider::GetNext(bool bAsync) {
	while (!m_bBreak) {
		if (!m_prov.get()) {
			if (m_filenames.empty()) {
				m_bEOF = true;
				return nullptr;
			}
			String fn = m_filenames[0];
			m_filenames.pop_front();
			EXT_LOCK (m_csProv) {
				m_prov.reset(CFilePacketProvider::FromFilename(fn));
				if (!m_sUserFilter.IsEmpty())
					m_prov->SetUserFilter(m_sUserFilter);
			}
		}
		if (ILP_SnifferPacket sp = m_prov->GetNext(bAsync))
			return sp;
		EXT_LOCK (m_csProv) {
			m_prov = 0;
		}
	}
	return nullptr;
}

int CFilesPacketProvider::Loop(IProcessPacket *iProcessPacket, int cnt) {
	while (!m_bBreak) {
		if (!m_prov.get()) {
			if (m_filenames.empty()) {
				m_bEOF = true;
				return 0;
			}
			String fn = m_filenames[0];
			m_filenames.pop_front();
			EXT_LOCK (m_csProv) {
				m_prov.reset(CFilePacketProvider::FromFilename(fn));
				if (!m_sUserFilter.IsEmpty())
					m_prov->SetUserFilter(m_sUserFilter);
			}
		}
		int n = m_prov->Loop(iProcessPacket, cnt);
		if (n <= 0) {
			EXT_LOCK (m_csProv) {
				m_prov = 0;
			}
		}
	}
	return 0;
}

void CFilesPacketProvider::SetUserFilter(RCString s) {
	m_sUserFilter = s;
}

void CPacketProvider::AdjustPacketMedium(const u_char *&data, int& len, byte& medium) {
	switch (medium)
	{
	case PROTO_NULL:
		{
			u_int family;
			memcpy((char *)&family, (char *)data, sizeof(family));
			data += 4;
			len -= 4;
			if ((family & 0xFFFF0000) != 0)				// This isn't necessarily in our host byte order; if this is
				family = ntohl(family);					// a DLT_LOOP capture, it's in network byte order, and if
			switch (family) {							// this is a DLT_NULL capture from a machine with the opposite
			case BSD_AFNUM_INET:					// byte-order, it's in the opposite byte order from ours.
				medium = PROTO_IP;				// If the upper 16 bits aren't all zero, assume it's byte-swapped.
				break;
			case BSD_AFNUM_INET6_BSD:
			case BSD_AFNUM_INET6_FREEBSD:
			case BSD_AFNUM_INET6_DARWIN:
				medium = PROTO_IPv6;
				break;
			case BSD_AFNUM_ISO:
				//!!!						isoclns_print(p, length, caplen);
				break;
			case BSD_AFNUM_APPLETALK:
				medium = PROTO_ATALK;
				break;
			case BSD_AFNUM_IPX:
				medium = PROTO_IPX;
				break;
			}
		}
		break;
	case DLT_LINUX_SLL:
		data += 2;
		len -= 2;
		medium = PROTO_ETHERNET;
		break;
	}
}

ILP_SnifferPacket CPacketProvider::GetNext(bool bAsync) {
	pcap_pkthdr *hdr;
	const u_char *data;

	//!!!int r = pcap_read_ex(m_pd,&hdr,&data);
	int r = pcap_next_ex(m_pd,&hdr,&data);
	switch (r)
	{
	case -2:
		m_bEOF = true;
	case 0:
		return nullptr;
	case -1: Throw(E_FAIL); //!!!
	case 1:
		{
			if (hdr->len != hdr->caplen)
				Throw(E_Sniffer_SnapLen);
			int len = hdr->caplen;
			byte medium = m_medium;
			AdjustPacketMedium(data, len, medium);
			ILP_SnifferPacket sp = new(len) SnifferPacket;
			sp->Flags = BLOCK_FLAG_ORIGINAL;
			sp->Medium = medium;
			sp->TimeStamp = hdr->ts;
			sp->Order = Order++;
			memcpy((byte*)sp->Data,data,len);

			return sp;
		}
	default:
		Throw(E_FAIL);
	}
}

int __stdcall PcapCheck(int r) {
	if (r < 0)
		Throw(E_Sniffer_WPCap);
	return r;
}

vector<CPacketProvider::PacketInterface> CPacketProvider::GetAllInterfaces() {
	char errbuf[PCAP_ERRBUF_SIZE] = "";
	vector<PacketInterface> r;
	pcap_if_t *p;
	if (::pcap_findalldevs(&p, errbuf) < 0)
		PcapThrow(errbuf);
	for (; p; p=p->next) {
		PacketInterface itf;
		itf.Name = p->name;
		if (p->description)
			itf.Description = p->description;
		for(pcap_addr *a=p->addresses; a; a=a->next) {
			CIpParams param;
			if (a->addr)
				param.m_addr = *a->addr;
			if (a->broadaddr)
				param.m_broadaddr = *a->broadaddr;
			if (a->netmask)
				param.m_netmask = *a->netmask;
			if (a->dstaddr)
				param.m_dstaddr = *a->dstaddr;
			itf.Params.push_back(param);
		}
		r.push_back(itf);
	}
	pcap_freealldevs(p);
	return r;
}

void CPacketProvider::OpenLive(RCString name) {
	char errbuf[PCAP_ERRBUF_SIZE];
	if (!(m_pd = ::pcap_open_live(name, 65535, 1, 1, errbuf)))
		PcapThrow(errbuf);
	m_medium = DltToMedium(::pcap_datalink(m_pd));
}

struct ProvIface {
	CPacketProvider *Prov;
	IProcessPacket *iProcessPacket;
};

void CPacketProvider::PcapHandlerProcessPacket(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt_data) {
	int len = hdr->caplen;
	if (len != hdr->caplen)
		Throw(E_Sniffer_SnapLen);
	ProvIface& provIface = *(ProvIface*)user;
	CPacketProvider *prov = provIface.Prov;	
	byte medium = prov->m_medium;
	AdjustPacketMedium(pkt_data, len, medium);
	SnifferPacket sp;
	sp.InitInStack();			// to prevent destroy
	sp.Flags = BLOCK_FLAG_ORIGINAL;
	sp.Medium = medium;
	sp.TimeStamp = hdr->ts;
	sp.Order = prov->Order++;
	sp.Data = pkt_data;
	sp.Size = len;
	provIface.iProcessPacket->ProcessPacket(sp);
}

int CPacketProvider::Loop(IProcessPacket *iProcessPacket, int cnt) {
	if (m_pd) {
		ProvIface provIface = { this, iProcessPacket };
		return PcapCheck(::pcap_loop(m_pd, cnt, &PcapHandlerProcessPacket, (u_char*)&provIface));
	} else {
		int sum = 0;
		while (true) {			
			ILP_SnifferPacket sp = GetNext();
			if (!sp || (cnt>0 && ++sum==cnt))
				break;
			iProcessPacket->ProcessPacket(*sp);
		}
		return sum;
	}
}

void CPacketProvider::PcapHandler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt_data) {
	((CPacketProvider*)user)->OnPacket(*hdr, ConstBuf(pkt_data, hdr->caplen));
}

int CPacketProvider::Loop(int cnt) {
//    cout << __FUNCTION__ << endl; //!!!D
	return PcapCheck(::pcap_loop(m_pd, cnt, &PcapHandler, (u_char*)this));
}

void CPacketProvider::BreakLoop() {
	pcap_breakloop(m_pd);
}

void CPacketProvider::SetUserFilter(RCString s) {
	bpf_program bpf;
	char *buf = (char*)alloca(s.Length+1);
	strcpy(buf, s);
	if (pcap_compile_nopcap(0xFFFF,pcap_datalink(m_pd),&bpf,buf,0,0)<0)
		Throw(1);      //!!!
	else
	{
		if (pcap_setfilter(m_pd, &bpf) < 0)
			Throw(E_FAIL);//!!!
	}
}

bpf_program CPacketProvider::Compile(RCString exp) {
	bpf_program fcode;
	if (pcap_compile(m_pd,&fcode,(char*)(const char*)exp,1,0) < 0)
	{
		cerr << pcap_geterr(m_pd) << endl;
		Throw(E_Sniffer_WPCap);
	}
	return fcode;
}

void CPacketProvider::SetFilter(bpf_program& fcode) {
	if (pcap_setfilter(m_pd,&fcode) < 0) {
		cerr << pcap_geterr(m_pd) << endl;
		Throw(E_Sniffer_WPCap);
	}
}

static void PrintCapBegins (const char* program_name, char* device) {
	DWORD dwVersion;
	DWORD dwWindowsMajorVersion;
	int ii,jj;
	char dev[256];
#ifdef WIN32
	dwVersion=GetVersion();
	dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
	if (dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4 || device[1])			// Windows '95
	{
		for(ii=0,jj=0;ii<128;ii++) 
				if (device[ii]=='\0') break; 
				else if (device[ii]!='\0') {dev[jj]=device[ii];jj++;}
		dev[jj]='\0';
		(void)fprintf(stderr, "%s: listening on %s\n",program_name, dev);
		(void)fflush(stderr);
	}
	else
#endif
	{
		for(ii=0,jj=0;ii<128;ii++) 
				if (device[ii]=='\0' && device[ii+1]=='\0') break; 
				else if (device[ii]!='\0') {dev[jj]=device[ii];jj++;}
		dev[jj++]='\0';
		dev[jj]='\0';
		fwrite(program_name, strlen(program_name), 1, stderr);
		fwrite(": listening on ", 15, 1, stderr);
		fwrite(dev, strlen(dev), 1, stderr); 
		fwrite("\n", 1, 1, stderr); 
		(void)fflush(stderr);
	}
}

CCapturePacketProvider::CCapturePacketProvider(const char *devName) {
	char error[PCAP_ERRBUF_SIZE] = "";
	try
	{
		if (!devName) {
			if (!(devName=pcap_lookupdev(error)))
				PcapThrow(error);
		} else {
			if (devName[0] == '0' && devName[1] == 0) {
				cerr << "Invalid adapter index" << endl;
				Throw(E_Sniffer_WPCap);
			}
			int devnum;
			if  ((devnum = atoi(devName)) != 0) {
				if (devnum < 0)
					Throw(E_Sniffer_WPCap);
				pcap_if_t *devpointer;
				if (pcap_findalldevs(&devpointer, error) < 0)
					PcapThrow(error);
				else {
					for (int i = 0; i < devnum-1; i++) {
						devpointer = devpointer->next;
						if (devpointer == NULL)
							Throw(E_Sniffer_WPCap);
					}
				}
				devName = devpointer->name;
			}
		}
		PrintCapBegins(Path::GetFileNameWithoutExtension(AfxGetCApp()->Argv[0]),(char*)devName);
		if (!(m_pd=pcap_open_live((char*)devName, 65535, true, SLEEP_TIME, error)))
			PcapThrow(error);
		m_medium = DltToMedium(pcap_datalink(m_pd));
	}
	catch (RCExc e)
	{
		cerr << e << endl;
		throw;
	}
}

CCapturePacketProviderEx::CCapturePacketProviderEx()
{
//!!  m_eng.Create();
}

ILP_SnifferPacket CCapturePacketProviderEx::GetNext(bool bAsync) {
	/*!!!
	while (true)
	{
	if (CBlockHeader *bh = m_eng.GetNextBlock())
	{
	int len = sizeof(CBlockHeader)+bh->m_len;
	CBlockHeader *nbh = (CBlockHeader*)new BYTE[len];
	memcpy(nbh,bh,len);
	m_eng.FreeLastBlock();
	return CPacket(nbh);
	}
	if (bAsync)
	return CPacket();
	Sleep(SLEEP_TIME);//!!!
	}    */
	return nullptr;
}

#if UCFG_XML && UCFG_WIN32
CXmlPacketProvider::CXmlPacketProvider(RCString filename)
	:	m_dom(new XmlDocument)
{
	m_dom.Load(filename);
	m_nodes = m_dom.SelectNodes("PACKETS/*");
}

ILP_SnifferPacket CXmlPacketProvider::GetNext(bool bAsync) {
	if (XmlElement npacket=m_nodes.NextNode()) {
		vector<BYTE> ar;
		String shex = npacket.InnerText;
		istringstream is(shex.c_str()); //!!!
		for (int b; is>>hex>>b;)
			ar.push_back((BYTE)b);
		ptr<SnifferPacket> sp = new(ar.size()) SnifferPacket;
		sp->Medium = (BYTE)atoi(npacket.GetAttribute("MEDIUM"));
		sp->Flags = BLOCK_FLAG_ORIGINAL;
		sp->TimeStamp =  DateTime(Convert::ToUInt64(npacket.GetAttribute("TIMESTAMP")));
		sp->Order = Convert::ToUInt64(npacket.GetAttribute("ORDER"));
		memcpy((byte*)sp->Data,&ar[0],ar.size());
		return sp;
	} else
		return nullptr;
}
#endif

#if UCFG_WIN32 && UCFG_EXTENDED
class CDialogProgress : public CDialog {
public:
	CStatic m_text;
	CBool m_bCanceled;

	void DoDataExchange(CDataExchange* pDX) {
		DDX_Control(pDX, IDC_TEXT, m_text);
	}

	void OnCancel() {
		m_bCanceled = true;
		CDialog::OnCancel();
	}
};

class CWpcapImporter : public CImporter {
	CImporter& m_importer;
	CDialogProgress m_dlg;
	size_t m_count;
	CWnd *m_wndParent;

	bool ImportPacket(SnifferPacket *sp) {
		if (!(++m_count & 0xF)) {
			m_dlg.m_text.Text = "Imported "+Convert::ToString(m_count)+" packets";
			m_dlg.m_text.Update();//!!!
			MSG msg;
			while (PeekMessage(&msg,0,0,0,PM_REMOVE))
				DispatchMessage(&msg);
			if (m_dlg.m_bCanceled)
				return false;
		}
		return m_importer.ImportPacket(sp);
	}
public:
	CWpcapImporter(CImporter& importer)
		:	m_importer(importer)
		,	m_count(0)
	{
		m_dlg.Create2(IDD_PROGRESS,m_wndParent=AfxGetMainWnd());
		m_dlg.Show();
		m_dlg.Text = AfxGetAppName();
		if (m_wndParent)
			m_wndParent->Enable(false);
	}

	virtual ~CWpcapImporter() {
		if (m_wndParent)
			m_wndParent->Enable();
	}
};

void __stdcall ImportSnifferFile(RCString filename, CImporter& importer) {
	CWaitCursor wc;
	CWpcapImporter impWrap(importer);
	unique_ptr<CFilePacketProvider> prov(CFilePacketProvider::FromFilename(filename));
	for (ILP_SnifferPacket sp; sp=prov->GetNext();)
		if (!importer.ImportPacket(sp))
			break;
}

void __stdcall WpcapFileImport(CImporter& importer) {
	CFileDialog fd(TRUE);
	fd.m_ofn.lpstrFilter = _T("TcpDump files (*.pcap)\0*.pcap\0")
		_T("NetMon files (*.cap)\0*.cap\0")
		_T("CommView files (*.ncf)\0*.ncf\0")
		_T("XML file (*.xml)\0*.xml\0")
		_T("All files (*.*)\0*.*\0");
	if (fd.DoModal() == IDOK)
		ImportSnifferFile(fd.GetPathName(),importer);
}
#endif	// UCFG_WIN32 && UCFG_EXTENDED

} // Snif::


#ifndef _PACKET32 //!!!
//!!!	#include <initguid.h>
//!!!	#include "ObjectData_i.c"
#endif

#if UCFG_WIN32	//!!!?
#	include "../wpcap/file_netxray.cpp"
#	include "../wpcap/file_netmon.cpp"
#	include "../wpcap/file_commview.cpp"
#endif

