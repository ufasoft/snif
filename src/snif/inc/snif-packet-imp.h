/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "sniffeng.h"

#ifdef WIN32
#	include <el/comp/driverloader.h>
#	include "pcap-int.h"
#endif

#if UCFG_SNIF_USE_WND
#	include <el/libext/win32/ext-wnd.h>
#endif

#if UCFG_SNIF_USE_PCAP
#	include "pcap-snif-eng.h"
#endif

namespace Snif {

void * __stdcall SnifferPacket::operator new(size_t size, int len) {
	if (len > MAX_PACKET_SIZE)
		Throw(E_FAIL);
#if UCFG_ADDITIONAL_HEAPS
	SnifferPacket *sp = (SnifferPacket*)SnifferPacketBase::operator new(size+len+2);//!!!(SnifferPacket*)new BYTE[size+len+2];
#else
	SnifferPacket *sp = (SnifferPacket*)new byte[size+len+2];
#endif
	sp->Size = len;
	sp->Data = (BYTE*)(sp+1);
	*(WORD*)(sp->Data+len) = 0;
	return sp;
}


/*!!!
SnifferPacket::SnifferPacket(CBlockHeader *pBlock, bool bOwner)
:	m_pBlock(pBlock)
,	m_bOwner(bOwner)
{
}

SnifferPacket::SnifferPacket(size_t size)
:	m_bOwner(true)
{
m_pBlock = (CBlockHeader*)new BYTE[sizeof(CBlockHeader)+size];
m_pBlock->m_len = size;
memset(m_pBlock+1,0,size);
}

SnifferPacket::~SnifferPacket() {
if (m_bOwner)
delete (BYTE*)m_pBlock;
}*/

ILP_SnifferPacket __stdcall SnifferPacket::FromSnifPacket(SnifferPacket& snifPacket) {
	ILP_SnifferPacket sp = new(snifPacket.Size) SnifferPacket;
	sp->TimeStamp = snifPacket.TimeStamp;
	sp->Order = snifPacket.Order;
	sp->Medium = snifPacket.Medium;
	sp->Adapter = snifPacket.Adapter;
	sp->Flags = snifPacket.Flags;
	memcpy((byte*)sp->Data, snifPacket.Data, snifPacket.Size);
	return sp;
}

#if !UCFG_SNIF_USE_PCAP

SnifferPacket::SnifferPacket(CBlockHeader *bh, UInt64 order)
:	Order(order)
{
	//!!!D	ENSURE_COPY_PROT
	if (!bh)
		return;
	FillHeader(bh);
	Data = (BYTE*)(this+1);
	memcpy(this+1,bh->m_data,Size);
}

void SnifferPacket::FillHeader(CBlockHeader *bh) {
	TimeStamp = bh->m_timeStamp;
	Medium = bh->m_medium;
	Adapter = LocalSnifEng().GetAdapter(bh->m_nDevice);
	Flags = bh->m_flags;
}
#endif // !UCFG_SNIF_USE_PCAP

#ifdef WIN32

ptr<SnifferPacket, NonInterlocked> __stdcall SnifferPacket::Load(IDispatch *disp) {
#if !UCFG_SNIF_USE_ODDB
	return nullptr;
#else
	COdObject ob = disp;
	Blob blob = AsOptionalBlob(ob.GetProperty("Data"));
	ptr<SnifferPacket> sp = new(blob.Size) SnifferPacket;
	memcpy((byte*)sp->Data, blob.constData(), blob.Size);
	sp->m_ob = ob;
	sp->TimeStamp = (FILETIME&)AsCurrency(ob.GetProperty("Timestamp")).int64;
	sp->Flags = (byte)Convert::ToInt32(ob.GetProperty("Flags"));
	sp->Medium = (byte)Convert::ToInt32(ob.GetProperty("Medium"));
	sp->Order = Convert::ToInt64(ob.GetProperty("Order"));
	return sp;
#endif
}

void SnifferPacket::Save(IDispatch *disp) {
#if UCFG_SNIF_USE_ODDB
	if (!m_ob) {
		COdClass cl(disp);
		m_ob = cl.CreateObject();
		CY cy;
		cy.int64 = (__int64&)TimeStamp.ToFileTime();
		m_ob.SetProperty("Timestamp", COleCurrency(cy));
		VARIANT v;
		v.vt = VT_BSTR;
		v.bstrVal = (BSTR)Data;
		m_ob.SetProperty("Data", v);
		m_ob.SetProperty("Order", long(Order));
		m_ob.SetProperty("Flags", Flags);
		m_ob.SetProperty("Medium", Medium);
	}
#endif
}
#endif

long SnifferPacket::GetProto() {
	if (Flags & BLOCK_FLAG_WAN)
		return PROTO_WAN;
	else switch (Medium) {
		//!!!  case PROTO_ATM://!!!ATM
case PROTO_ETHERNET:
case PROTO_WAN:
	return PROTO_ETHERNET;
case PROTO_TOKENRING:
case PROTO_SLIP:
case PROTO_IP:
case PROTO_IEEE802_11:
case PROTO_IEEE802_11_RADIO:
	return Medium;
default:
	return PROTO_UNKNOWN;
	}
}

/*!!!void SnifferPacket::TakeOwnership() {
if (!m_bOwner)
{
size_t len = sizeof(CBlockHeader)+m_pBlock->m_len;
m_pBlock = (CBlockHeader*)memcpy(new BYTE[len],m_pBlock,len);
m_bOwner = true;
}
}*/


vector<ptr<CSnifEng> > CSnifEng::s_all;
CPointer<ThreadBase> CSnifEng::s_LoopingThread;
vector<CFilterBind*> CFilterBind::s_all;

#ifdef WIN32
	CHeap g_heapPacket;
#endif


byte __stdcall DltToMedium(int linktype) {
	switch (linktype) {
	default:
		TRC(0,"Unsupported DLT!");
	case DLT_LINUX_SLL:
		return (byte)linktype;
	case DLT_EN10MB:  return PROTO_ETHERNET;
	case DLT_IEEE802: return PROTO_TOKENRING;
	case DLT_IEEE802_11: return PROTO_IEEE802_11;
	case DLT_IEEE802_11_RADIO: return PROTO_IEEE802_11_RADIO;
	case DLT_PPP_SERIAL:
	case DLT_PPP:     return PROTO_WAN;
	case DLT_SLIP:    return PROTO_SLIP;
	case DLT_RAW:     return PROTO_IP;
	case DLT_NULL:    return PROTO_NULL;
	}
}

int __stdcall MediumToDlt(byte medium) {
	switch (medium) {
	case PROTO_ETHERNET:  return DLT_EN10MB;
	case PROTO_TOKENRING: return DLT_IEEE802;
	case PROTO_IEEE802_11: return DLT_IEEE802_11;
	case PROTO_IEEE802_11_RADIO: return DLT_IEEE802_11_RADIO;
	case PROTO_WAN:				return DLT_PPP;
	case PROTO_SLIP:			return DLT_SLIP;
	case PROTO_IP:
	case PROTO_IP6:
	case PROTO_RAW:				return DLT_RAW;
	case PROTO_NULL:			return DLT_NULL;
	default:
		return medium;
	}
}

CAdapterFilter::CAdapterFilter(BYTE medium)
	:	m_bLooped(true)
	,	m_queue(DEFAULT_PACKET_QUEUE_SIZE)
	,	m_medium(medium)
{
	STATIC_ASSERT_POWER_OF_2(DEFAULT_PACKET_QUEUE_SIZE+1);

	CommonInit();
}

CAdapterFilter::CAdapterFilter(Adapter *ad)
	:	m_bLooped(false)
	,	m_queue(DEFAULT_PACKET_QUEUE_SIZE)
	,	m_medium((byte)ad->GetMedium())
{
	CommonInit();
	m_arAdapter.push_back(ad);
	//!!!  ad->m_filters.push_back(this);
}

void CAdapterFilter::CommonInit() {
#if !UCFG_SNIF_USE_PCAP
	Flags = 0;
#endif
	//!!!  m_maxQueueSize = DEFAULT_PACKET_QUEUE_SIZE;
	m_bOverflow = false;
	m_bResetted = true;
}

CAdapterFilter::~CAdapterFilter() {
	Unbind();
}

/*!!!
void CAdapterFilter::Bind()
{
for (int i=SnifEng().Adapters.size(); i--;)
{
Adapter *ad = SnifEng().GetAdapters()[i].get();
if (ad->m_desc.m_medium == m_medium)
{
m_arAdapter.push_back(ad);
ad->m_filters.push_back(this);
}
}
}*/

void CAdapterFilter::Unbind() {
	if (m_bind)
		m_bind->Remove(this);
}

void CAdapterFilter::SetFilter(bpf_program& bpf) {
	ptr<CBpfProgram> p(new CBpfProgram);
	*p = bpf;
	m_bpfProgram = p;
}

void CAdapterFilter::OnReceived(SnifferPacket *sp) {
	++m_nAccepted;
	if (Callback)
		Callback->ProcessPacket(*sp);
}

void CAdapterFilter::FilterPacket(SnifferPacket *sp) {
	if (sp->Flags & BLOCK_FLAG_SKIP)
		return;
	
	if (ptr<CBpfProgram> bpf = m_bpfProgram)
		if (!bpf_filter(bpf->bf_insns, (byte*)sp->Data, (u_int)sp->Size, (u_int)sp->Size))		//!!! FreeBSD requires non-const u_char* arg
			return;

	ThreadBase *curThread = Thread::get_CurrentThread();

	if (m_bind->m_bDirectThread || CSnifEng::s_LoopingThread == curThread || LoopingThread == curThread) {
		OnReceived(sp);
	} else {
		if (m_bResetted = m_bResetted || m_queue.empty()) {
			if (m_queue.size() < m_queue.capacity()) {
				TRC_SHORT(3, "P");

				//!!!D					CLock lock(m_cs); //!!!
				if (sp->IsHeaped())
					m_queue.push_back(sp);
				else
					m_queue.push_back(SnifferPacket::FromSnifPacket(*sp));
				if (m_queue.size() == 1)
					m_evRead.Set();
				return;
			}
			else {
				m_bOverflow = true;
				m_bResetted = false;
			}
		}
		Interlocked::Increment(SnifEngBase::s_nUserLost);
		Interlocked::Increment(SnifEngBase::s_nUserLostSum);
	}
}


mutex g_mtxSnifEng;
CFilterBind g_packetFB(true, false); //!!!?

/*!!!
void *CBlockHeader::operator new(size_t size, size_t len)
{
if (len > MAX_PACKET_SIZE)
Throw(E_FAIL);::SnifferPa
CBlockHeader *bh = (CBlockHeader*)new BYTE[size+len];
bh->m_len = len;
return bh;
}*/

CFilterBind::CFilterBind(bool bEnabled, bool bSync)
	:	m_bEnabled(bEnabled)
	,	m_timerPeriod(TimeSpan::MaxValue)
	,	m_medium2filters(256)
	,	m_bSync(bSync)
{
	if (m_bSync) {
		EXT_LOCK (g_mtxSnifEng) {
			s_all.push_back(this);
		}
	} else
		s_all.push_back(this);
}

CFilterBind::~CFilterBind() {
	Unbind();
}

void CFilterBind::Unbind() {
	if (m_bSync) {
		EXT_LOCK (g_mtxSnifEng) {
			Ext::Remove(s_all, this);
		}
	} else
		Ext::Remove(s_all, this);
}

void CFilterBind::Add(CAdapterFilter *f) {
	EXT_LOCK (g_mtxSnifEng) {
		m_filters.push_back(f);
		m_medium2filters[f->m_medium].push_back(f);
		f->m_bind = this;
	}
}

void CFilterBind::Remove(CAdapterFilter *f) {
	EXT_LOCK (g_mtxSnifEng) {
		Ext::Remove(m_filters, f);
		Ext::Remove(m_medium2filters[f->m_medium], f);
	}
}

void CFilterBind::ProcessFilters(byte medium, SnifferPacket *sp, Adapter *ad) {
	CFilters& filters = m_medium2filters[medium];
	for (int i=0, nFilter=filters.size(); i<nFilter; ++i) {
		CAdapterFilter& af = *filters[i];
		if (!af.m_arAdapter.size() || find(af.m_arAdapter.begin(), af.m_arAdapter.end(), ad)!=af.m_arAdapter.end())
			af.FilterPacket(sp);
	}
}

///!!!CPointer<CLocalSnifEng> g_pSniffEng;

CSnifEng::CSnifEng()
	:	m_bEnabled(true)
{
#if UCFG_UPGRADE
	EnsureUpgrade();
#endif
	m_bAutoDelete = false;
	s_all.push_back(this);
}

CSnifEng::~CSnifEng() {
}

void CSnifEng::Dispose() {
	if (Valid()) {
		Stop();
		Join();
	}
	Remove(s_all, this);
}

/*!!!
int CSnifEng::LoopCount(int nMax)
{
int rMin=0, rMax=0;
for (int i=m_adapters.size(); i--;)
{
Adapter& ad = *m_adapters[i];
for (int j=ad.m_filters.size(); j--;)
{
CAdapterFilter& f = *ad.m_filters[j];
}
}
return rMax-rMin;
}*/

//!!!CBool CSnifEng::s_bStop;

int CSnifEng::Loop(const TimeSpan& timespan) {	
	Keeper<CPointer<ThreadBase> > threadKeeper(s_LoopingThread, Thread::get_CurrentThread());

	if (!SnifEngBase::s_I->m_bAdaptersOpened)
		SnifEngBase::s_I->OpenAdapters();
	

#if !UCFG_SNIF_USE_PCAP
	CLocalSnifEng *leng = (CLocalSnifEng*)SnifEngBase::s_I;

	class CThreadedSnifCallback : public CSnifCallback {
		typedef CSnifCallback base;
	public:
		CLocalSnifEng *m_pEng;

		bool ProcessPacket(SnifferPacket& snifPacket) {
			EXT_LOCK (g_mtxSnifEng) {
				m_pEng->Process(&snifPacket, snifPacket.Adapter);
			}
			return true;
		}
	} cb;
	cb.m_pEng = leng;
#endif

	typedef vector<pair<CAdapterFilter*,ILP_SnifferPacket> > CVec;
	CVec ar;
	ar.reserve(PACKETS_AT_ONCE*10);

	int r = 0;

	for (DateTime beg = DateTime::UtcNow();;) {
		int N = 0;

#if !UCFG_SNIF_USE_PCAP
		if (!CLocalSnifEng::s_StartInSeparateThread || !CLocalSnifEng::s_LoopInSeparateThread) {
			
			N += leng->LoopPackets(PACKETS_AT_ONCE, cb);
		}
#endif

		ar.clear();

		int m = 0;
		if (CAppBase::s_bSigBreak) {
			Throw(E_EXT_SignalBreak);
		}
		DateTime now = DateTime::UtcNow();
		{
			//!!!      CLock lock(g_mtxSnifEng);
			for (size_t i=CFilterBind::s_all.size(); i--;) {
				CFilterBind *b = CFilterBind::s_all[i];
				for (size_t j=b->m_filters.size(); j--;) {
					CAdapterFilter *f = b->m_filters[j];
					f->CheckOverflow();
					//!!!D          CLock lockFilter(f->m_cs);
					if (f->m_bLooped) {
						for (int k=PACKETS_AT_ONCE; k-- && !f->m_queue.empty(); f->m_queue.pop_front(), ++m)
							ar.push_back(make_pair(f,f->m_queue.front()));
					}
				}        
				if (now-b->m_onTimerPrev > b->m_timerPeriod) {
					b->OnFilterTimer();
					b->m_onTimerPrev = now;
				}
			}
		}
		for (CVec::iterator i=ar.begin(); i!=ar.end(); ++i) {
//			TRC_SHORT(2, "_");
			i->first->OnReceived(i->second);
		}
		//!!!		TRC_SHORT(1,n << " ");
		r += m+N;
		if (now-beg>timespan)
			break;		
		if (!m && !N) {
			if (timespan != TimeSpan::MaxValue)
				break;
#if !UCFG_SNIF_USE_PCAP
			if (!CLocalSnifEng::s_StartInSeparateThread) {
				bool b = leng->WaitPackets();
				if (!b && timespan != TimeSpan::MaxValue)
					break;
			} else
#endif
				::usleep(SLEEP_TIME*1000);
		}
	}
	return r;
}

void CSnifEng::AllLoadSettings() {
#if UCFG_WIN32 && UCFG_EXTENDED
	RegistryKey key(AfxGetCApp()->KeyCU, "SelectedAdapters");
	if (key.KeyExists("localhost"))
		SnifEng().LoadSettings(RegistryKey(key, "localhost"));
	else
		SnifEng().SaveSettings(RegistryKey(key, "localhost"));
#endif
#if UCFG_SNIF_REMOTE
	vector<String> subkeys = key.GetSubKeyNames();
	for (int i=0; i<subkeys.size(); i++)
		if (atoi(subkeys[i]))
		{
			CRemoteSnifEng *reng = new CRemoteSnifEng();
			reng->m_regSubkey = subkeys[i];
			reng->LoadSettings(RegistryKey(key,subkeys[i]));
			reng->Start();
		}
#endif
}

void CSnifEng::AllSaveSettings() {
#if UCFG_WIN32 && UCFG_EXTENDED
	AfxGetCApp()->KeyCU.DeleteSubKeyTree("SelectedAdapters");
	RegistryKey key(AfxGetCApp()->KeyCU,"SelectedAdapters");
	for (int i=0; i<s_all.size(); i++) {
		CSnifEng *eng = s_all[i].get();
		RegistryKey k(key,eng->m_bLocal ? "localhost" : Convert::ToString(i));
		(HKEY)k; // Ensure create
		eng->SaveSettings(k);
	}
#endif
}

mutex SnifEngBase::s_mtx;
SnifEngBase *SnifEngBase::s_I;

volatile Int32 CSnifEng::s_nDriverLost,
	CSnifEng::s_nUserLost,
	CSnifEng::s_nUserLostSum;

class SnifferAnnoyer : public CAnnoyer {
	void OnAnnoy() {
		if (DWORD nDriverLost = Interlocked::Exchange(SnifEngBase::s_nDriverLost, 0L))
			cerr << "Driver buffer overflow: " << nDriverLost << " packets lost" << endl;
		if (DWORD nCurrentLost = Interlocked::Exchange(SnifEngBase::s_nUserLost, 0L))
			cerr << "User buffer overflow: " << nCurrentLost << " packets lost" << endl;
	}
} g_snifferAnnoyer;


SnifEngBase& __stdcall SnifEng(bool bBindWifi) {
	EXT_LOCK (SnifEngBase::s_mtx) {
		if (!SnifEngBase::s_I) {
	#if UCFG_SNIF_USE_PCAP
			SnifEngBase::s_I = new PcapSnifEng;
	#else
			SnifEngBase::s_I = new CLocalSnifEng;
	#endif
			SnifEngBase::s_I->m_bBindWifi = bBindWifi;
			SnifEngBase::s_I->Create();
		}
		return *SnifEngBase::s_I;
		/*!!!
		if (!g_pSniffEng.get())
		{
		g_pSniffEng = new CLocalSnifEng;
		g_pSniffEng->Create();
		}
		return *g_pSniffEng;
		*/
	}
}

/*!!!R
void SetSniffEng(CLocalSnifEng *eng)
{
g_pSniffEng = eng;
}
*/

#if UCFG_SNIF_USE_WND
ptr<CWindowNotifier> g_windowNotifier;
#endif


/*!!!
class EthernetAdapter : public Adapter
{
public:
EthernetAdapter()
{
m_oidCurrentAddress = OID_802_3_CURRENT_ADDRESS;
}
};

class TokenRingAdapter : public Adapter
{
public:
TokenRingAdapter()
{
m_oidCurrentAddress = OID_802_5_CURRENT_ADDRESS;
}
};

class WanAdapter : public Adapter
{
public:
WanAdapter()
{
m_oidCurrentAddress = OID_WAN_CURRENT_ADDRESS;
}
};

*/


void CSnifEng::Process(SnifferPacket *sp, Adapter *ad) {
	//!!!  ptr<SnifferPacket> sp = new SnifferPacket(bh,true);
	if (!m_bEnabled || !ad->Enabled)
		return;
	//!!!  CSingleLock lock(&g_mtxSnifEng,true);
	for (int i=0, nBind=CFilterBind::s_all.size(); i<nBind; ++i) {
		CFilterBind& bind = *CFilterBind::s_all[i];
		if (bind.m_bEnabled && (!bind.m_bLocal || m_bLocal)) {
			bind.m_dtLastPacket = sp->TimeStamp;

			bind.ProcessFilters(sp->Medium, sp, ad);
			bind.ProcessFilters(255, sp, ad);
		}
	}
}

#ifdef _WIN32

class InvalidSignatureExc : public Exc {
public:
	InvalidSignatureExc()
		:	Exc(HRESULT_FROM_WIN32(ERROR_INVALID_IMAGE_HASH), AfxProcessError(HRESULT_FROM_WIN32(ERROR_INVALID_IMAGE_HASH))
		+"\nTo solve the problem:"
		+"\n  Reboot the Windows."
		+"\n  When the system restarts, use \"F8\" to get to the \"Advanced Boot Options\" menu"
		+"\n  and select \"Disable Driver Signature Enforcement\"")
	{}
};

void CSnifEng::LoadSettings(RegistryKey& key) {
	vector<String> subkeys = key.GetSubKeyNames();
	CSnifEng::CAdapters ar = GetAdapters();
	for (size_t i=ar.size(); i--;) {
		Adapter& ad = *ar[i];
		ad.Enabled = false;
		String intName = ad.m_desc.Name;
		for (int j=0; j<subkeys.size(); j++) {
			RegistryKey k(key, subkeys[j]);
			if ((String)k.TryQueryValue("Name", "") == intName) {
				ad.Enabled = true;
#if UCFG_SNIF_WIFI
#				define STATUS_NDIS_DOT11_MEDIA_IN_USE   ((NTSTATUS)0xC0232001L)

				if ((String)k.TryQueryValue("Mode", "") == "Monitor")
					if (ad.Type == EAdapterType::Wifi || ad.Type == EAdapterType::LegacyWifi) {
						try {
							DBG_LOCAL_IGNORE(E_WIFI_CMD_BUSY);
							DBG_LOCAL_IGNORE_NAME(STATUS_NDIS_DOT11_MEDIA_IN_USE | 0x20000000, ignSTATUS_NDIS_DOT11_MEDIA_IN_USE);							

							((WifiAdapter*)&ad)->MonitorModeP = true;
							((WifiAdapter*)&ad)->ChannelNum = (DWORD)k.TryQueryValue("Channel", 1);
						} catch (RCExc) {
						}
					}
#endif
					break;
			}
		}			
	}
}

void CSnifEng::SaveSettings(RegistryKey& key) {
	CSnifEng::CAdapters ar = GetAdapters();
	for (int i=0; i<ar.size(); i++) {
		Adapter& ad = *ar[i];
		if (ad.Enabled) {
			RegistryKey k(key,Convert::ToString(i));
			k.SetValue("Name",ad.m_desc.Name);
#if UCFG_SNIF_WIFI
			if ((ad.Type == EAdapterType::Wifi || ad.Type == EAdapterType::LegacyWifi) && ((WifiAdapter*)&ad)->MonitorModeP) {
				k.SetValue("Mode", "Monitor");
				k.SetValue("Channel", ((WifiAdapter*)&ad)->ChannelNum);
			} else
				k.SetValue("Mode", "Normal");
#endif
		}
	}
}
#endif


//!!!int Adapter::s_id;

bool Adapter::s_bEnableByDefault = true;

Adapter::Adapter(CThreadRef *tr)
:	base(tr)
,	m_oidCurrentAddress(0)
,	m_bLoopback(false)
//!!!		m_id(s_id++)
{
	m_bEnabled = s_bEnableByDefault;
}

void Adapter::Send(const ConstBuf& mb, bool bDefer) {
#ifdef WIN32
	if (m_oidCurrentAddress != OID_WAN_CURRENT_ADDRESS)
		SendEx((Buf&)mb, bDefer);		//!!!?
#endif
	/*!!!D  BYTE *p = (BYTE*)alloca(mb.m_len+4);
	memcpy(p+4,mb.m_p,mb.m_len);
	SendEx(CMemBlock(p,mb.m_len+4));*/
}


//!!! #include <initguid.h>

//!!! #include "ObjectData_i.c"

CBpfProgram& CBpfProgram::operator=(const bpf_program& fp) {
	if (this != &fp) {
		Destroy();
		memcpy(bf_insns=new bpf_insn[bf_len=fp.bf_len],fp.bf_insns,sizeof(bpf_insn)*fp.bf_len);
	}
	return _self;
}

CBpfProgram CBpfProgram::All() {
	CBpfProgram r;
	r.bf_insns = new bpf_insn[r.bf_len = 1];
	bpf_insn& b = r.bf_insns[0];
	ZeroStruct(b);
	b.code = BPF_RET;
	b.k  =0xFFFF;
	return r;
}

void CAdapterFilter::CheckOverflow() {
	if (SnifEngBase::s_nDriverLost || SnifEngBase::s_nUserLost)
		g_snifferAnnoyer.Request();
}

int CAdapterFilter::ReadOp(int cnt, CSnifCallback& cb) {
	int N = 0;	

	while (true) {
		CheckOverflow();
		if (CAppBase::s_bSigBreak) {
			if (!N)
				N = -1;
			return N;
		}
		while (!m_queue.empty() && (cnt<0 || cnt--)) {
			
			/*!!!R
			if (m_queue.empty()) {
				if (N || exchange(bWaited,true))
					break;
				Thread::Sleep(200); //!!!
				continue;
			}*/
			cb.ProcessPacket(*m_queue.front());
			m_queue.pop_front();
			N++;
		}


#if !UCFG_SNIF_USE_PCAP
		CLocalSnifEng *leng = (CLocalSnifEng*)SnifEngBase::s_I;
		if (!CLocalSnifEng::s_StartInSeparateThread && cnt) {

			InterlockedSemaphore sem(CLocalSnifEng::s_CaptureSemaphore);
			if (sem.TryLock()) {
				bool bWaiting = false;

				Keeper<CPointer<ThreadBase> > threadKeeper(LoopingThread, Thread::get_CurrentThread());
				Keeper<CPointer<CSnifCallback> > callbackKeeper(Callback, &cb);

				class CThreadedSnifCallback : public CSnifCallback {
				public:
					CLocalSnifEng *m_pEng;
					CSnifCallback *m_oldCb;

					bool OnCheckBreak() override {
						return m_oldCb->OnCheckBreak();
					}

					bool ProcessPacket(SnifferPacket& snifPacket) override {
						EXT_LOCK (g_mtxSnifEng) {
							m_pEng->Process(&snifPacket, snifPacket.Adapter);
						}
						return true;
					}
				} ncb;
				ncb.m_oldCb = &cb;
				ncb.m_pEng = leng;

				m_nAccepted = 0;
				int k = leng->LoopPackets(cnt==-1 ? cnt : cnt-N, ncb);
				N += m_nAccepted;
				if (N+k == 0) {
					if (leng->WaitPackets()) {
						m_nAccepted = 0;
						k = leng->LoopPackets(cnt==-1 ? cnt : cnt-N, ncb);
						N += m_nAccepted;
					}
				}
				return N;
			}
		}
#endif
	}

	return N;
}


#if UCFG_UPGRADE
static mutex s_csUpgrade;
unique_ptr<CUpgrade> g_pUpgrade; 

void AFXAPI EnsureUpgrade() {
#if UCFG_COPY_PROT
	EXT_LOCK (s_csUpgrade) {
		if (!g_pUpgrade.get())
			g_pUpgrade.reset(new CUpgrade);
	}
#endif
}
#endif

} // Snif::

using namespace Snif;

void __cdecl ExPacketCloseAll() {
#if UCFG_SNIF_USE_WND
	if (g_windowNotifier) {
		g_windowNotifier->Stop();
		g_windowNotifier->WaitStop();
		g_windowNotifier = nullptr;
	}
#endif


	while (!CSnifEng::s_all.empty())
		CSnifEng::s_all[0]->Dispose();

#if UCFG_UPGRADE
	EXT_LOCK (s_csUpgrade) {
		//!!!  SetSniffEng(0);
		g_pUpgrade = 0;
	}
#endif
}

AtExitRegistration s_atexitPacket(&ExPacketCloseAll);



#ifdef X_DEBUG

#include <atlutil.h>
using namespace ATL;

#include <stack-trace.h>


class CStackDumpHandler : public IStackDumpHandler {
public:
	void __stdcall OnBegin() {
		cerr << "Begin" << endl;
	}

	void __stdcall OnEntry(void *pvAddress, LPCSTR szModule, LPCSTR szSymbol) {
		cerr << pvAddress << "\t" << szModule << "\t" << szSymbol << endl;
	}

	void __stdcall OnError(LPCSTR szError) {
		cerr << szError << endl;
	}

	void __stdcall OnEnd() {
		cerr << "End" << endl;
	}
};

ostream& operator<<(ostream& os, const CONTEXT& c)
{
	os << "EAX " << Convert::ToString(c.Eax, "X8") << '\n'
		 << "EBX " << Convert::ToString(c.Ebx, "X8") << '\n'
		 << "ECX " << Convert::ToString(c.Ecx, "X8") << '\n'
		 << "EDX " << Convert::ToString(c.Edx, "X8") << '\n'
		 << "ESI " << Convert::ToString(c.Esi, "X8") << '\n'
		 << "EDI " << Convert::ToString(c.Edi, "X8") << '\n'
		 << "ESP " << Convert::ToString(c.Esp, "X8") << '\n'
		 << "EBP " << Convert::ToString(c.Ebp, "X8") << '\n'
		 << "EFlags " << Convert::ToString(c.EFlags, "X8") << '\n'
		 << "EIP " << Convert::ToString(c.Eip, "X8") << '\n';
	return os;
}


static void GetReport(EXCEPTION_POINTERS *ExceptionInfo)
{
	ostream& os = cerr;

	OSVERSIONINFO ov = System.Version;
	os << "OS Version: " << ov.dwMajorVersion << '.' << ov.dwMinorVersion	<< '.'
		 << ov.dwBuildNumber << ' ' << ov.szCSDVersion << '\n';
	try
	{
		CVersionInfo vi(System.ExeFilePath);	
		os << vi.InternalName << '\t' << VersionToStr(vi.GetFileVersionN()) << "\n";
	}
	catch (RCExc)
	{}
	SYSTEM_INFO si = System.Info;
	if (si.dwNumberOfProcessors != 1)
		os << "Number of CPU: " << si.dwNumberOfProcessors << '\n';
	os << '\n';
	EXCEPTION_RECORD& er = *(EXCEPTION_RECORD*)ExceptionInfo->ExceptionRecord;
	os << "Code: " << Convert::ToString(er.ExceptionCode, "X8") << '\n'
		 << "Addr: " << er.ExceptionAddress << "\n\n"
	   << *ExceptionInfo->ContextRecord << "\n\n";

	os << "Stack:\n";
	DWORD *p = (DWORD*)ULongToPtr(ExceptionInfo->ContextRecord->Esp);
	for (int i=0; i<40; i++)
	{
		os << p << ":\t";
		for (int j=0; j<4; j++)
			os << Convert::ToString(*p++, "X8") << ' ';
		os << '\n';
	}	
	os << '\n';
}


static class CStackDump : public CUnhandledExceptionFilter
{
	LONG Handle(EXCEPTION_POINTERS *ExceptionInfo)
	{
		GetReport(ExceptionInfo);

		StackTrace(*ExceptionInfo->ContextRecord);

		CStackDumpHandler dumper;
		AtlDumpStack(&dumper);
		::MessageBox(0, "End", "Packet", MB_OK);
		return EXCEPTION_EXECUTE_HANDLER;
	}
} s_stackDump;


#endif


#if !UCFG_SNIF_USE_PCAP

void LogMessage(RCString s) {
	cerr << s << endl;
}
#endif


