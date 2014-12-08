/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include <snif.h>

#if !UCFG_SNIF_USE_PCAP
#	include <pcap-int.h>
#endif

#include "tcpapi.h"

#include "resource.h"

#if UCFG_SNIF_WIFI
#	include "802_11.h"
#endif

namespace Snif {

CProtoEngBase *CProtoEngBase::s_pMain;
CBool CProtoEngBase::s_bEnableLog;

void CProtoEngBase::MakeMain() {
	s_pMain = this;

#ifdef WIN32	
#	if UCFG_EXTENDED
	RegistryKey key(AfxGetCApp()->KeyCU, "Options"); //!!!
	s_bEnableLog = (DWORD)key.TryQueryValue("EnableLog", DWORD(1));  //!!!
	m_sLogDir = key.TryQueryValue("LogDir", (LPCTSTR)(AfxGetCApp()->AppDataDir));
	Directory::CreateDirectory(m_sLogDir);
#	endif
#else
	s_bEnableLog = true;
	m_sLogDir = "/var/log/snif";
#	if UCFG_EXTENDED
	Directory::CreateDirectory(m_sLogDir);
#	endif
#endif	
}

void CProtoEngBase::SetCombinedFilter() {
#if UCFG_SNIF_FILTER
	try {
		for (size_t i=m_filters.size(); i--;) {
			CAdapterFilter& f = *m_filters[i];
			String s;
			if (f.m_medium == PROTO_ETHERNET) //!!!? or NdisMedium802_5
				s = m_sIPFilter;
			if (!m_sUserFilter.IsEmpty()) {
				if (!s.IsEmpty())
					s += " and ";
				s += "("+m_sUserFilter+")";
			}
			bpf_program bpf;
			char *buf = (char*)alloca(s.Length+1);
			strcpy(buf, s);
			if (pcap_compile_nopcap(0xFFFF, MediumToDlt(f.m_medium), &bpf, buf, 0, 0)<0)
				Throw(1);
			f.SetFilter(bpf);
		}
	} catch (RCExc) {
		m_sUserFilter = "";
		throw;
	}
#endif
}

void CProtoEngBase::SetUserFilter(RCString s) {
	m_sUserFilter = s;
	if (m_prov.get())
		m_prov->SetUserFilter(s);
	SetCombinedFilter();
}

void CProtoEngBase::LoadFilter() {
#if UCFG_EXTENDED
	try {
		SetUserFilter(RegistryKey(AfxGetCApp()->KeyCU, "Filter").TryQueryValue("TcpdumpString", ""));
	} catch (RCExc) {
		cerr << "Invalid User Filter" << endl;
	}

#	if UCFG_SNIF_WIFI
	try {
		SetWifiKeys(AfxGetCApp()->KeyCU.TryQueryValue("WepKeys", vector<String>()));
	} catch (RCExc e) {
		cerr << e << endl;
	}
#	endif
#endif
}

void CProtoEngBase::SetIPFilter(RCString s) {
	m_sIPFilter = s;
	SetCombinedFilter();
}

CProtoEng::CProtoEng(EOnlyEthernet)
	:	CProtoEngBase(false)
	,	m_nAdapter(0)
{
	/*!!!	m_eth = CreateEthernet();
	m_tokenRing = CreateTokenRing(); 
	m_802_11 = Create802_11(); 
	*/

	m_eth = StaticCast<MACObj>(PluginClassBase::CreatePlugin(PROTO_ETHERNET,this));
	m_tokenRing = StaticCast<MACObj>(PluginClassBase::CreatePlugin(PROTO_TOKENRING,this));
	Add(m_eth);
	Add(m_tokenRing);
#if UCFG_SNIF_WIFI
	m_802_11 = StaticCast<MACObj>(PluginClassBase::CreatePlugin(PROTO_IEEE802_11_RADIO,this));
	Add(m_802_11);
#endif
}

CProtoEng::CProtoEng(bool bEnabled)
	:	CProtoEngBase(bEnabled)
	,	m_options("A:DF:?hi:qr:tv:w:C:")
	,	m_nAdapter(0)
{
	m_eth = StaticCast<MACObj>(PluginClassBase::CreatePlugin(PROTO_ETHERNET,this));
	m_tokenRing = StaticCast<MACObj>(PluginClassBase::CreatePlugin(PROTO_TOKENRING,this));
#if UCFG_SNIF_WIFI
	m_options += "k:";
	m_802_11 = StaticCast<MACObj>(PluginClassBase::CreatePlugin(PROTO_IEEE802_11_RADIO,this));
#endif
	m_pppoe = StaticCast<MACObj>(PluginClassBase::CreatePlugin(PROTO_PPPOES,this));
	m_ppp = StaticCast<MACObj>(PluginClassBase::CreatePlugin(PROTO_WAN,this));
	m_slip = StaticCast<MACObj>(PluginClassBase::CreatePlugin(PROTO_SLIP,this));

	/*!!!
	m_eth = CreateEthernet();
	m_tokenRing = CreateTokenRing();
	m_802_11 = Create802_11(); 
	m_ppp = CreatePPP();
	m_slip = CreateSLIP();*/

	//m_ip = new IpObj;

	m_ip = StaticCast<IpObjBase>(PluginClassBase::CreatePlugin(PROTO_IP, this));
	m_ip->m_bSkipDuplicates = true; //!!!Q maybe place in TcpObj?

#if UCFG_SNIF_IPV6
	m_ip6 = StaticCast<IpObjBase>(PluginClassBase::CreatePlugin(PROTO_IP6, this));
	m_ip6->m_bSkipDuplicates = true; //!!!Q maybe place in TcpObj?
#endif

	PluginClassBase::CreatePlugin(PROTO_GRE,this);


	/*!!!
	m_eth->Subscribe(m_ip,PROTO_IP);
	m_tokenRing->Subscribe(m_ip,PROTO_IP);
	m_802_11->Subscribe(m_ip,PROTO_IP);
	m_ppp->Subscribe(m_ip,PROTO_IP);
	m_slip->Subscribe(m_ip,PROTO_IP);
	*/
	/*!!!
	m_netbeui = new NetBEUIObj;
	m_eth->Subscribe(m_netbeui,PROTO_NETBEUI);
	m_tokenRing->Subscribe(m_netbeui,PROTO_NETBEUI);
	m_802_11->Subscribe(m_netbeui,PROTO_NETBEUI);
	m_ppp->Subscribe(m_netbeui,PROTO_NETBEUI);
	*/

	m_netbeui = PluginClassBase::CreatePlugin(PROTO_NETBEUI,this);

	Add(m_eth);
	Add(m_tokenRing);
#if UCFG_SNIF_WIFI
	Add(m_802_11);
#endif
	Add(m_ppp);
	Add(m_slip);
	Add(m_ip);
#if UCFG_SNIF_IPV6
	Add(m_ip6);
#endif
}

void CProtoEng::PrintUsage() {
	cerr << "Usage:\n"
		"prog <options>" << endl;
}

bool CProtoEng::ProcessPacket(SnifferPacket& sp) {

#ifdef X_DEBUG //!!!R
	if (sp.Order == 4000)
		sp.Order = sp.Order;
#endif

	m_dtLastPacket = sp.TimeStamp;
	ProcessFilters(sp.Medium, &sp, 0);
	return true;

	/*!!!
	for (size_t j=m_filters.size(); j--;) {
		CAdapterFilter& f = *m_filters[j];
		if (f.m_medium==sp->Medium && bpf_filter(f.m_bpfProgram.bf_insns, sp->Data, (u_int)sp->Size, (u_int)sp->Size))
			f.OnReceived(sp);
	}*/
	/*!!!
	case PROTO_NULL: memmove(bh->m_data,bh->m_data+4,(bh->m_len-=4)+2);
	case PROTO_RAW:       iPlugin = m_ip; break;
	iPlugin->Analyze(iSP);
	else
	{
	cerr << "Unknown protocol:\t " << proto << endl; //!!!
	Throw(E_FAIL);
	}*/
}

int CProtoEng::Loop(const TimeSpan& timespan) {
	if (m_prov.get()) {
		m_bDirectThread = true;
		if (timespan == TimeSpan::MaxValue)
			return m_prov->Loop(this);
		else {
			DateTime beg = DateTime::UtcNow();
			int n = 0;
			while (true) {
				if (CAppBase::s_bSigBreak) {
					Throw(E_EXT_SignalBreak);
				}
				if (ILP_SnifferPacket sp = m_prov->GetNext(true)) {
					++n;
					ProcessPacket(*sp);
					if (DateTime::UtcNow()-beg > timespan)
						break;
				} else if (m_prov->m_bEOF)
					break;
				else
					break;
				//!!!Sleep(SLEEP_TIME);
			}
			return n;
		}
	} else
		return CSnifEng::Loop(timespan);
}


ptr<ArpObj> CProtoEng::GetArpObj() {
	if (!m_arp) {
		m_arp = StaticCast<ArpObj>(PluginClassBase::CreatePlugin(PROTO_ARP,this));
		//    m_eth->Subscribe(m_arp,PROTO_ARP);
		//    m_tokenRing->Subscribe(m_arp,PROTO_ARP);
	}
	return m_arp;
}

ptr<IpObjBase> CProtoEng::GetIpObj() {
	if (!m_ip) {
		m_ip = StaticCast<IpObjBase>(PluginClassBase::CreatePlugin(PROTO_IP, this));
		//    m_eth->Subscribe(m_ip,PROTO_IP);
		//    m_tokenRing->Subscribe(m_ip,PROTO_IP);
		//    m_ppp->Subscribe(m_ip,PROTO_IP);
	}
	return StaticCast<IpObjBase>(m_ip);
}

#if UCFG_SNIF_IPV6
ptr<IpObjBase> CProtoEng::GetIp6Obj() {
	if (!m_ip6) {
		m_ip = StaticCast<IpObjBase>(PluginClassBase::CreatePlugin(PROTO_IP6,this));
		//    m_eth->Subscribe(m_ip6,PROTO_IP);
		//    m_tokenRing->Subscribe(m_ip6,PROTO_IP);
		//    m_ppp->Subscribe(m_ip6,PROTO_IP);
	}
	return StaticCast<IpObjBase>(m_ip6);
}
#endif

ptr<MACObj> CProtoEng::GetMACObj(BYTE medium) {
	switch (medium)
	{
	case PROTO_ETHERNET: return StaticCast<MACObj>(m_eth);
	case PROTO_TOKENRING: return StaticCast<MACObj>(m_tokenRing);
	default: Throw(E_FAIL);
	}
}

ptr<ITcpPlugin> CProtoEng::GetTcpObj() {
	if (!m_tcp) {
		ptr<IpObjBase> ipObj = GetIpObj();
#if UCFG_SNIF_IPV6
		ptr<IpObjBase> ip6Obj = GetIp6Obj();
#endif
		m_tcp = StaticCast<ITcpPlugin>(PluginClassBase::CreatePlugin(PROTO_TCP, this));

		//    ipObj->Subscribe(m_tcp=CreateTCP(),PROTO_TCP);
		//    ipObj->Subscribe(m_tcp->m_icmpObj,PROTO_ICMP);
	}
	return StaticCast<ITcpPlugin>(m_tcp);
}

} // Snif::
