/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "msgan.h"

#pragma warning(disable: 4073)
#pragma init_seg(lib)  // to be first in ininitialization order


namespace Snif {


PFNLogMessage PLogMessage;

static mutex g_csLruMessage;
static LruCache<String> g_lruMessage;

void LruLogMessage(RCString s) {
	EXT_LOCK (g_csLruMessage) {
		if (!g_lruMessage.insert(s).second)
			return;
	}
	PLogMessage(s);
}


CTraceCategory TRCAT_P("TRCAT_P");
CTraceCategory TRCAT_HTTP("HTTP");


bool g_opt_write_traffic = false; //!!! set true only with _DEBUG
bool g_opt_message_as_xml = false;
bool g_opt_ResolveEnabled = true;
bool g_opt_SaveFiles = false;



/*!!!
int LookForPattern(const ConstBuf &buf, const ConstBuf &pat)
{
	if (buf.m_len > pat.m_len)
		for(int i=0; i<buf.m_len; i++)
		{
			int j;
			for (j=0; (j<pat.m_len) && ((i+j)<buf.m_len); j++)
				if (buf.m_p[i+j] != pat.m_p[j])
					goto repeat;
			if (j == pat.m_len)
				return i;
	repeat:
			;
		}
	return -1;
}

// -----------------------
// Ожидание совпадения маски в данных потока
// -------------

bool ConnectionManager::do_wantedmatch( ptr<Analyzer> an, TcpStream *stm, uint dir )
{
	ConstBuf buf = stm->GetData();
	ConstBuf pat = ConstBuf(an->MatchPattern(dir));
	TRC(1, "* " << dir << " Looking for match: " << buf.m_len << " " << pat.m_len);
	int i = LookForPattern(buf, pat);
	if (i < 0)
		return false;
	// Here we got a match
	TRC(1, "* Got it at " << i);
	an->Process( Blob(buf.m_p, i), dir );
	stm->Skip(an->m_processed[dir]);
	stm->Skip(pat.m_len);
	TRC(1, "* Skip: " << an->m_processed[dir] + pat.m_len << " bytes");
	return true;
}

*/

void StreamClient::Unbind(AnalyzerStream *as) {
	AnalyzerStreams.erase(CAnalyzerStreams::const_iterator(as));
	if (AnalyzerStreams.empty()) {
		if (m_ci)
			m_ci->Clients[m_dir] = 0;
	}
}

void StreamClient::Adjust() {
	UInt64 minOffset = INT_MAX;
	for (CAnalyzerStreams::iterator i=AnalyzerStreams.begin(), e=AnalyzerStreams.end(); i!=e; ++i)
		minOffset = min(minOffset, (UInt64)(i->m_offset));
	m_blob.Replace(0, size_t(minOffset-m_offset), ConstBuf(0, 0));
	m_offset = minOffset;
}

AnalyzerStream::AnalyzerStream()
	:	m_wanted(0)
	,	m_processed(0)
	,	m_state(ASTATE_INITIAL)
	,	m_rstage(0)
{
}

AnalyzerStream::~AnalyzerStream() {
	if (StreamClient)
		StreamClient->Unbind(this);
}

void AnalyzerStream::SetStreamClient(Snif::StreamClient *sc) {
	m_offset = (StreamClient = sc)->m_offset;
	sc->AnalyzerStreams.insert(sc->AnalyzerStreams.begin(), _self);
}

ConstBuf AnalyzerStream::GetData() {
	size_t off = size_t(m_offset-StreamClient->m_offset);
	return ConstBuf(StreamClient->m_blob.constData()+off, StreamClient->m_blob.Size-off);
}

void AnalyzerStream::Skip(size_t n) {
	if (m_analyzer->m_bDeleted)
		return;
	u_int64_t offset = m_offset+n;
	if (offset > StreamClient->m_offset+StreamClient->m_blob.Size)
		Throw(E_FAIL);
	m_offset = offset;
	StreamClient->Adjust();
}

void AnalyzerStream::Process() {
	for (ConstBuf mb; (mb=GetData()).Size;) {
		if (m_analyzer->m_bDeleted)
			break;
		switch (m_state) {
		case ASTATE_NO_NEED:
			if (mb.Size > 10000)
				Skip(mb.Size/2);
			break;
		case ASTATE_NEED_MATCH:
			if (const BYTE *p = mb.Find(m_matchPattern)) {
				size_t off = p-mb.P;
				Process(ConstBuf(p,mb.Size-off));
				Skip(off+exchange(m_processed,0));
				continue;
			} else
				Skip(max(0,int(mb.Size)-int(m_matchPattern.Size)));
			break;
		case ASTATE_NEED_MORE:
			if (mb.Size >= m_wanted) {
				TRC(3, "Wait for bytes: " << (DWORD)m_wanted);
		        Process(mb);
				Skip(exchange(m_processed, 0));
				continue;
			}
			break;
		case ASTATE_OK:
			Process(mb);
			if (m_processed) {
				Skip(exchange(m_processed, 0));
				continue;
			}
		}
		break;
	}
}

int s_dAnalyzer;

Analyzer::Analyzer() {
	m_arStm[0] = m_arStm[1] = 0;
#ifdef X_DEBUG//!!!D
	m_cnt = s_dAnalyzer++;
#endif
}

Analyzer::~Analyzer() {
	if (m_class) 
		m_class->m_objects.erase(AnalyzerObjects::const_iterator(this));
}

void Analyzer::Capture() {
	m_bCaptured = true;
	if (m_ci) {
		m_ci->PotentialAnalyzers.erase(CAnalyzerList::const_iterator(this));
		m_ci->ReleaseAllAnalyzers();
		m_ci->Analyzers.push_back(_self);
	}
}

void Analyzer::Delete() {
	if (!m_bDeleted) {
		m_bDeleted = true;
		if (m_ci) {
			m_ci->PotentialAnalyzers.erase(CAnalyzerList::const_iterator(this));
			m_ptrSelf.reset();
		}
	}
}

void Analyzer::OverflowProtection() {
	if (m_arStm[0]->GetData().Size+m_arStm[1]->GetData().Size > MAX_RECOGNIZE)
		Delete();
}

AnalyzerClassBase::AnalyzerClassBase()
	:	m_id(0)
	,	Priority(255)
{
	ConnectionManager::I->m_arClass.push_back(this);
}

struct AnalyzerClassPred {
	AnalyzerClassBase *m_cl;

	AnalyzerClassPred(AnalyzerClassBase *cl)
		:	m_cl(cl)
	{}

	bool operator()(const AnalyzerListHook& hook) const {
		Analyzer& an = (Analyzer&)hook;
		return an.m_class == m_cl;
	}
};

AnalyzerClassBase::~AnalyzerClassBase() {
	TRC(1, GetName());

	ConnectionManager& cm = *ConnectionManager::I;
	for (CTcpAnalyzer::CMapConn::iterator i=cm.m_mapConn.begin(), e=cm.m_mapConn.end(); i!=e; ++i) {
		CConnectionInfo& ci = *(CConnectionInfo*)i->second.get();
		
		for (CAnalyzerList::iterator it; (it = find_if(ci.Analyzers.begin(), ci.Analyzers.end(), AnalyzerClassPred(this))) != ci.Analyzers.end();)
			((Analyzer&)*it).Delete();
		for (CAnalyzerList::iterator it; (it = find_if(ci.PotentialAnalyzers.begin(), ci.PotentialAnalyzers.end(), AnalyzerClassPred(this))) != ci.PotentialAnalyzers.end();)
			((Analyzer&)*it).Delete();
	}


	Remove(cm.m_arClass, this);
	cm.m_priority2anclass.erase(m_i);
}

void AnalyzerClassBase::Create(RCString name) {
	m_name = name;
	ConnectionManager& cm = *ConnectionManager::I;
	m_i = cm.m_priority2anclass.insert(make_pair(Priority,this));
	for (CTcpAnalyzer::CMapConn::iterator i=cm.m_mapConn.begin(), e=cm.m_mapConn.end(); i!=e; ++i) {
		CConnectionInfo& ci = *(CConnectionInfo*)i->second.get();
		ci.Add(CreateObject());
	}
}

ptr<Analyzer> AnalyzerClassBase::Insert(Analyzer *an) {
	m_objects.insert(m_objects.begin() , *an);
	an->m_class = this;
#ifdef _DEBUG
	an->m_id = ++m_id;
//	if (!(m_id & 0xF))
//		TRC(10,"Analyzer::count = " << int(m_objects.size()));
#endif
	return an;
}

CMessageAnalyzerClass::CByNameMap& AFXAPI CMessageAnalyzerClass::ByNameMap() {			// to prevent multiple static instances
	static CByNameMap s_t;
	return s_t;
}

CMessageAnalyzerClass::CMessageAnalyzerClass(RCString name)
	:	m_name(name)
	,	Type(ATYPE_OPTIONAL)
	,	Users(_self)
{
	ByNameMap()[m_name.ToUpper()] = this;
}


CMessageAnalyzer *CMessageAnalyzerClass::Activate() {
	m_bActive = true;

	CMessageAnalyzer *r = CreateObject();
	ConnectionManager::I->m_setActivatedAnalyzers.insert(r);

#if UCFG_SNIF_USE_DB
	DbActivate();
#endif
	return r;
}

ptr<User> CMessageAnalyzerClass::CreateUser() {
	return new User;
}

bool ConnectionManager::s_bEnableWebActivity = true;

void ConnectionManager::ParallelThread::Execute() {
	Name = "ConnectionManager::ParallelThread";

	try {
		while (!m_bStop) {
			bool bWasExecution = false;
			EXT_LOCK (ConnectionManager::I->MtxAnalyzerClasses) {
				for (CMessageAnalyzerClass::CByNameMap::iterator i=CMessageAnalyzerClass::ByNameMap().begin(), e=CMessageAnalyzerClass::ByNameMap().end(); i!=e; ++i) {
					try {
						bWasExecution |= i->second->Execute();
					} catch (RCExc) {
					}
				}
			}
			if (!bWasExecution)
				Sleep(SLEEP_TIME);
		}
	} catch (RCExc e) {
		if (e.HResult != E_EXT_ThreadStopped)
			throw;
	}
	for (CMessageAnalyzerClass::CByNameMap::iterator i=CMessageAnalyzerClass::ByNameMap().begin(), e=CMessageAnalyzerClass::ByNameMap().end(); i!=e; ++i)
		i->second->Finalize();
}

ConnectionManager *ConnectionManager::I;

ConnectionManager::ConnectionManager()
	:	MailboxFormat("UNIX") /*!!!,
		m_db(&m_ws),
		m_rsAnalyzers(&m_db),
		m_rsUsers(&m_db),
		m_rsMessages(&m_db)*/
{
	I = this;
//!!!	m_httpAnalyzerClass = new HttpAnalyzerClass;
}

ConnectionManager::~ConnectionManager() {
	if (m_parallelThread) {
		m_parallelThread->Stop();
		m_parallelThread->Join();
	}

	if (I)
		CloseAll();
//!!!	m_httpAnalyzerClass = 0;
#ifdef _DEBUG
	TRC(1, "\n\n!! Connection Manager is being destroyed, doing a full dump");
	TRC(1, "* Recognized streams:");
//!!!	DumpMap(m_tcp2ans);
	TRC(1, "\n* Streams are being recognized by:");
//!!!	DumpMap(m_recog);
#endif
}

void AFXAPI ConnectionManager::CloseAll() {
	I->Unbind();
	EXT_LOCK (I->MtxAnalyzerClasses) {
		I->m_setActivatedAnalyzers.clear();
	}
	I->m_tr.StopChilds();
#if UCFG_SNIF_USE_DB
	I->DbThread = nullptr;
#endif

	/*!!!D
#ifdef _DEBUG //!!!D
	for (CTcp2Info::iterator i=I->m_tcp2info.begin(); i!=I->m_tcp2info.end(); ++i)
	{
		CConnectionInfo& ci = i->second;
		if (ci.Analyzers.size())
		{
			ptr<Analyzer> a = ci.Analyzers[0];
			i = i;
		}
	}
#endif
	*/

/*!!!
#if UCFG_SNIF_USE_DB
	I->m_rsUsers = 0;
	I->m_db.m_conn = 0;
#endif
	*/

/*!!!R #if !UCFG_SNIF_USE_PCAP
	WpcapCloseAll();
#endif */

	I = 0;
}

//!!!------------------------------------
const char *traceDatabase = "TRACE";

#ifdef USE_DAO

	IMPLEMENT_DYNAMIC(CException,CObject)

	void ATLTRACE(const char* cat,int lev, const char*s,...)
	{
		va_list ptr;
		va_start(ptr, s);
		vfprintf(stderr, s, ptr);
	}

	void AfxTryCleanup()
	{}

	void AfxThrowLastCleanup()
	{}

	AFX_EXCEPTION_LINK::AFX_EXCEPTION_LINK()
	{}

	CDaoFieldExchange::CDaoFieldExchange(unsigned int,class CDaoRecordset *,void *)
	{}

	void CDaoFieldExchange::DeleteCacheValue(struct CDaoFieldCache *,unsigned long)
	{}
	//-----------------------------------------------
#endif


void ConnectionManager::Start(bool bStartIfEmpty) {

#if UCFG_SNIF_USE_DB
#	if UCFG_WIN32
	if ((DWORD)RegistryKey(AfxGetCApp()->KeyCU, "Options").TryQueryValue("SaveToDB", DWORD(1)))
#	endif
		(DbThread = new class DbThread)->Start();
#endif
	for (CMessageAnalyzerClass::CByNameMap::iterator i=CMessageAnalyzerClass::ByNameMap().begin(), e=CMessageAnalyzerClass::ByNameMap().end(); i!=e; ++i) {
		if (i->second->Type == ATYPE_MANDATORY)
			i->second->Activate();
	}

	if (m_classesToLoad.empty() && bStartIfEmpty) {
		for (CMessageAnalyzerClass::CByNameMap::iterator i=CMessageAnalyzerClass::ByNameMap().begin(), e=CMessageAnalyzerClass::ByNameMap().end(); i!=e; ++i)
			if (!i->second->m_bActive && i->second->Type == ATYPE_OPTIONAL)
				i->second->Activate();
	}
	TRC(0, HttpAnalyzerClass::I->m_subscriber.m_set.size() << " subscribers");

	for (set<String>::iterator i=m_classesToLoad.begin(); i!=m_classesToLoad.end(); ++i)
		if (!CMessageAnalyzerClass::ByNameMap()[*i]->m_bActive)
			CMessageAnalyzerClass::ByNameMap()[*i]->Activate();
	(m_parallelThread = new ParallelThread)->Start();
}

/*!!!
// Anaysis of recognized stream

void ConnectionManager::Analyze(StreamMap::iterator istm)
{
	TRC(1, "* Analyze");
	Analyzers &an_list = istm->second;
	for (int a=an_list.size(); a--;)
	{
		ptr<Analyzer> an = an_list[a];
		uint dir[2] = { SERVER2CLIENT, CLIENT2SERVER };
		TcpStream *stm[2] = { istm->first->GetInStream(), istm->first->GetOutStream() };
		for (uint k=0; k<2; k++)
		{
			int d = dir[k];
			TcpStream *tstm = stm[k];
			an->m_dt = max(m_dtLastPacket,tstm->m_tcpMan.m_dtLastPacket);
			for (ConstBuf mb; (mb=tstm->GetData()).m_len>0;)
			{
				switch (an->m_state[d])
				{
				case Analyzer::NeedMatch:
					{
						bool ret = true;
						while (an->State(d) == Analyzer::NeedMatch && ret)
							ret = do_wantedmatch(an,tstm,d);
						if (an->State(d) != Analyzer::NeedMatch )
							continue;
					}
					break;
				case Analyzer::NeedMore:
					{
						size_t wanted = an->WantedBytes(d);
						while (an->State(d) == Analyzer::NeedMore && tstm->GetData().m_len >= wanted)
						{
							an->Process(tstm->GetData(),d); //!!! was "wanted bytes"
							tstm->Skip(an->m_processed[d]);
						}
						if (an->State(d) != Analyzer::NeedMore)
							continue;
					}
					break;
				case Analyzer::Ok:
					{
						size_t offset = 0;
						try
						{
							while (tstm->GetData().m_len > 0 && an->State(d) == Analyzer::Ok )
							{
								mb = tstm->GetData();
								ConstBuf dmb(mb.m_p + offset,mb.m_len-offset);
								TRC(1, "* Normal processing");
								TRC(1, dmb);
								an->Process(dmb,d);
								uint processed = an->m_processed[d];
								if (processed == 0)
									break;
								TRC(1, "* " << processed << " bytes processed, skipping");
								if (processed <= tstm->GetData().m_len)
									tstm->Skip(processed);
								else
								{
									TRC(1, "! analyzer has processed (" << processed << ") more than it was passed (" << tstm->GetData().m_len << ") !");
									throw E_ProcessingFailed();
								}
							}
						}
						catch (E_InsufficientData)
						{
						}
						if (an->State(d) != Analyzer::Ok)
							continue;
					}
					break;
				case Analyzer::BadStream:
//!!!reprocess:;
					{
						TRC(1, "* Bad Stream " << TcpStreamInfo( istm->first ).dump());
						an_list.erase(an_list.begin()+a);
						goto next_analyzer;
					} 
				}
				break;
			}
			if (an->IsNewStream())	// Обработчик желает добавить новых условных обработчиков
			{
				TRC(1, "* Conditional Analyzer is added");
				m_conds.push_back(an->NewAnalyzer() );
			}
		} // for(k)
next_analyzer: ;
	} // for(an)
	bool no_one_need_it = true;
	for (uint a=an_list.size(); a--; )
		if (an_list[a]->State(CLIENT2SERVER) != Analyzer::BadStream && an_list[a]->State(SERVER2CLIENT) != Analyzer::BadStream )
		{
			no_one_need_it = false;
			break;
		}
		else
			an_list.erase( an_list.begin() + a );
	if (no_one_need_it || an_list.empty())
	{
		TRC(1, "* No one needs this stream: " << TcpStreamInfo( istm->first ).dump());
		ptr<TcpConnection> c = istm->first;
		m_tcp2ans.erase(istm);
		c->Delete(); //!!!
	}
}

// -----------------------
// Распознование
// -------------
// Поток распознается всеми доступными анализаторами

void ConnectionManager::Recognize(StreamMap::iterator irec)
{
	TRC(1, "* Recognize");
	Analyzers &ans = irec->second;
	uint dir[2] = { SERVER2CLIENT, CLIENT2SERVER };
	TcpStream *stm[2] = { irec->first->GetInStream(), irec->first->GetOutStream() };
	for (uint i=ans.size(); i--;)
	{
		Analyzer *a = ans[i];
		for (uint k=0;k<2;k++)
		{
			int d = dir[k];
			TcpStream *tstm = stm[k];
			ConstBuf buf = tstm->GetData();
			switch (a->RState(d))
			{
			case Analyzer::Asis:
				{
					TRC(1, "*R " << a->m_class->GetName() << " is processing data as is");
					uint offset = a->m_offsets[k];
					a->Recognize(ConstBuf(buf.m_p + offset, buf.m_len-offset),d);
					a->m_offsets[k] += a->m_processed[d];
				}
				break;
			case Analyzer::NeedMore:
				TRC(1, "*R STUB: waiting for at least" << a->WantedBytes(d) << " bytes");
				break;
			case Analyzer::NeedMatch:
				{
					TRC(1, "*R " << d << " "<< a->m_class->GetName() << " is waiting for a match to recognize");
					ConstBuf pat = ConstBuf(a->MatchPattern(d));
					uint offset = a->m_offsets[k];
					TRC(1, "*R offset in stream buffer: " << offset);
					while (a->RState(d) == Analyzer::NeedMatch && offset < buf.m_len ) 
					{
						ConstBuf frame = ConstBuf(buf.m_p + offset, buf.m_len-offset);
						TRC(1, "*R " << a->m_class->GetName() << " is looking for match in " << frame.m_len << ", pattern " << pat.m_len);
						int match = LookForPattern(frame, pat);
						if (match < 0)
							break;
						// Here we got a match
						TRC(1, "*R Got a match at " << match);
//!!!D						a->m_cTcp = irec->first;
						a->Recognize(ConstBuf(buf.m_p + offset, match ), d );
						offset += match + pat.m_len;
					}
					a->m_offsets[k] = offset;
				}
				break;
			case Analyzer::Ok:
				{
					TRC(1, "*R " << a->m_class->GetName() << " has recognized the stream");
	//!!!D				m_anoff.erase(a);
					TRC(1, "*R Skip processed bytes during recognize: " << a->m_processed[CLIENT2SERVER] << " " 
						<< a->m_processed[SERVER2CLIENT]);
					stm[CLIENT2SERVER]->Skip(a->m_processed[CLIENT2SERVER]);
					stm[SERVER2CLIENT]->Skip(a->m_processed[SERVER2CLIENT]);
					m_tcp2ans[irec->first].push_back(a);
					Analyze(m_tcp2ans.find(irec->first));
					m_recog.erase( irec );
				}
				return;
			case Analyzer::BadStream:
				{
					TRC(1, "*R " << a->m_class->GetName() << " has refused the stream");
					ans.erase( ans.begin() + i );
				}
				goto next_analyzer;
			}
		}
next_analyzer: ;
	}
	if (ans.empty())
	{
		TRC(1, "* Stream was refused by everybody, rejecting");
		DropConnection( irec->first );
	}
	else if ( stm[0]->GetData().m_len + stm[1]->GetData().m_len > MAX_RECOGNIZE )
	{
		TRC(1, "* Stream was not recognized, buffer limit " << MAX_RECOGNIZE << " exceeded");
		DropConnection( irec->first );
	}
	else
		TRC(1, "* " << MAX_RECOGNIZE << " " << stm[0]->GetData().m_len << " " << stm[1]->GetData().m_len << " in recognize buffer");
}
*/

/*!!!
ptr<Analyzer> ConnectionManager::CreateAnalyzer(AnalyzerClassBase *cl, TcpConnection *c)
{
	ptr<Analyzer> an = cl->CreateObject();
	an->m_cTcp = c;
	an->m_info = TcpStreamInfo(c);
	return an;
}

// -----------------------
// Предварительный анализ
// -------------
// Проверяются условия на совпадения потока, определенные для класса анализаторов,
// и дополнительные условия, возникшие в процессе анализа (только один раз)

void ConnectionManager::PreAnalyze(TcpConnection *c)
{
	TRC(1, "* PreAnalyze");
	for (int i=m_arClass.size(); i--;)
	{
		AnalyzerClassBase *cl = m_arClass[i];
		Conditions conds = cl->Preferred();
		for (int j=conds.size(); j--;)
		{
			if ((*conds[j])(c))
			{
				TRC(1, "* Match stream condition for " << cl->GetName());
				m_tcp2ans[c].push_back(CreateAnalyzer(cl,c));
				Analyze(m_tcp2ans.find(c));
				return;
			}
		}
	}

	for (int i=m_conds.size(); i--;)
	{
		if ((*(m_conds[i].first))(c))
		{
			TRC(1, "* Match analyzer extra condition");
			m_tcp2ans[c].push_back(m_conds[i].second);
			m_conds.erase( m_conds.begin() + i );
			Analyze( m_tcp2ans.find(c) );			
			return;
		}
	}

	TRC(1, "* No stream condition matched" );
	Analyzers& ar = m_recog[c];
	for (int i=m_arClass.size(); i--;)
		ar.push_back(CreateAnalyzer(m_arClass[i],c));
	Recognize(m_recog.find(c));
}
*/

void CConnectionInfo::SwapStreams() {
	swap(Clients[0], Clients[1]);
	swap(m_client0.m_dir, m_client1.m_dir);
	swap(DstEndPoint, SrcEndPoint);	
}

bool CConnectionInfo::TrySwapStreams() {
	if (GetWasSYN())
		return false;
	SwapStreams();
	return true;
}

void Analyzer::SwapStreams() {
	m_bSwapped = !m_bSwapped;
//!!!	if (m_ci)
//!!!		m_ci->TrySwapStreams();
//!!!	swap(m_outStm,m_inStm);
	m_arStm[0]->IsOut = false; //!!!
	m_arStm[1]->IsOut = true;
}

void AnalyzerStream::EnsureIncoming() {
	if (m_analyzer->m_ci && !m_analyzer->m_ci->GetWasSYN() && IsOut)
		m_analyzer->SwapStreams();
}

void AnalyzerStream::EnsureOutgoing() {
	if (m_analyzer->m_ci && !m_analyzer->m_ci->GetWasSYN() && !IsOut)
		m_analyzer->SwapStreams();
}

void LineAnalyzerStream::Process(const ConstBuf& data) {
	m_state = ASTATE_OK;
	switch (m_rstage) {
	case 1:
		if (BinaryMode) {
			BinaryMode = false;
			ProcessBinary(ConstBuf(data.P, m_processed = exchange(m_wanted, m_defaultWanted)));
		} else if (const byte *p = (const BYTE*)memchr(data.P,'\n', data.Size)) {
			size_t len = (m_processed=p-data.P+1)-1;
			if (len && data.P[len-1]=='\r')
				len--;
			if (memchr(data.P, 0, len))
				m_analyzer->Delete();
			else
				ProcessLine(AString((const char*)data.P, len));
		}
	}
}

struct PriorityLess {
	inline bool operator()(const AnalyzerListHook& x, const AnalyzerListHook& y) const {
		return ((Analyzer&)x).m_class->Priority < ((Analyzer&)y).m_class->Priority;
	}
};

void CConnectionInfo::Add(Analyzer *a, bool bAtEnd) {
	if (!Clients[0])
		Clients[0] = &m_client0;
	a->m_arStm[0]->SetStreamClient(Clients[0].get());
	if (!Clients[1])
		Clients[1] = &m_client1;
	a->m_arStm[1]->SetStreamClient(Clients[1].get());
	a->m_ci = this;

	a->m_ptrSelf = a;
	if (bAtEnd)
		PotentialAnalyzers.push_back(*a);
	else {
		CAnalyzerList::iterator it = lower_bound(PotentialAnalyzers.begin(), PotentialAnalyzers.end(), *a, PriorityLess());
		PotentialAnalyzers.insert(it, *a);
	}
}

void CConnectionInfo::ReleaseAllAnalyzers() {
	while (!Analyzers.empty())
		((Analyzer&)Analyzers.front()).Delete();
	while (!PotentialAnalyzers.empty()) {
		((Analyzer&)PotentialAnalyzers.front()).Delete();
	}
}

CConnectionInfo::~CConnectionInfo() {
	while (!Analyzers.empty()) {
		ptr<Analyzer> a = &static_cast<Analyzer&>(Analyzers.front());
		a->Finish();
		a->Delete();
	}
	ReleaseAllAnalyzers();
}

ptr<TcpConnection> ConnectionManager::CreateTcpConnectionObject(CTcpMan& tcpMan, ITcpConnection *conn) {
	CConnectionInfo *ci = new CConnectionInfo;
	ptr<TcpConnection> r(ci);
	ci->Init(tcpMan, _self, conn);
	return r;
}

void ConnectionManager::CreatedConnection(TcpConnection *c) {
	CConnectionInfo& ci = *static_cast<CConnectionInfo*>(c);
	
	ci.SrcEndPoint=c->GetSrcEndPoint();
	ci.DstEndPoint=c->GetDstEndPoint();
//!!!	CHostResolver::I().Resolve(ci.SrcEndPoint.GetIP());
//!!!	CHostResolver::I().Resolve(ci.DstEndPoint.GetIP());

	for (Cpriority2anclassMultimap::iterator i=m_priority2anclass.begin(), e=m_priority2anclass.end(); i!=e; ++i)
		ci.Add(i->second->CreateObject(), true);
	base::CreatedConnection(c);
}

void CConnectionInfo::Update() {
	if (Analyzers.empty()) {
LAB_BEGIN:
		for (CAnalyzerList::iterator i=PotentialAnalyzers.begin(), e=PotentialAnalyzers.end(); i!=e; ++i) {
			ptr<Analyzer> a = &(Analyzer&)*i;
			if (!a->m_bRecognitionTryed) {
				a->m_bRecognitionTryed = true;
				if (a->TryRecognize()) {
					PotentialAnalyzers.erase(CAnalyzerList::const_iterator(a.get()));
					Analyzers.push_back(*a);
					return;
				}
				if (a->m_bDeleted)
					goto LAB_BEGIN;			// TryRecognize() can change PotentialAnalyzers
			}
		}
		while (!PotentialAnalyzers.empty()) {
			CAnalyzerList::iterator it = PotentialAnalyzers.begin();
			PotentialAnalyzers.erase(it);
			Analyzers.push_back(*it);
		}
	}
}

void CConnectionInfo::ProcessStream(int dir) {
	while (true) {
		for (CAnalyzerList::iterator i=Analyzers.begin(), e=Analyzers.end(); i!=e;) {
			CAnalyzerList::iterator j(i++);					// Analyzer can change Analyzers list
			ptr<Analyzer> a = &(Analyzer&)*j;
			if (AnalyzerStream *stm = a->m_arStm[dir])
				try {
					stm->Process();
				} catch (RCExc) {
					a->Delete();
				}
			if (a->m_bCaptured)
				break;
		}
		if (Analyzers.empty()) {
			Update();
			if (Analyzers.empty())
				break;
		} else
			break;
	}
}

void ConnectionManager::UpdatedConnection(TcpConnection *c) {
	for (Cpriority2anclassMultimap::iterator i=m_priority2anclass.begin(), e=m_priority2anclass.end(); i!=e; ++i) {
		try {
			i->second->InThreadExecute();
		} catch (RCExc) {
		}
	}

	CConnectionInfo& ci = *static_cast<CConnectionInfo*>(c);

	TcpStream& os = c->OutStream;
	size_t olen, ilen;
	{
		ConstBuf mbO = os.GetData();
		if (olen = mbO.Size) {
			if (ci.Clients[0])
				ci.Clients[0]->m_blob.Replace(ci.Clients[0]->m_blob.Size,0,mbO);
			os.Skip(mbO.Size);
		}
	}
	TcpStream& is = c->InStream;
	{
		ConstBuf mbI = is.GetData();
		if (ilen = mbI.Size) {
			if (ci.Clients[1])
				ci.Clients[1]->m_blob.Replace(ci.Clients[1]->m_blob.Size,0,mbI);
			is.Skip(mbI.Size);
		}
	}
	TRC(3, ci.SrcEndPoint << " > " << ci.DstEndPoint << "\t out:" << olen << " in:" << ilen);
	ci.Update();
	if (olen && ci.Clients[0]) {
		m_dtLastPacket = c->m_tcpMan->m_dtLastPacket;
		m_lastSrcEndPoint = ci.SrcEndPoint;
		m_lastDstEndPoint = ci.DstEndPoint;
		ci.ProcessStream(0);
	}
	if (ilen && ci.Clients[1]) {
		m_dtLastPacket = c->m_tcpMan->m_dtLastPacket;
		m_lastSrcEndPoint = ci.DstEndPoint;
		m_lastDstEndPoint = ci.SrcEndPoint;
		ci.ProcessStream(1);
	}

	for (CAnalyzerList::iterator i=ci.Analyzers.begin(), e=ci.Analyzers.end(); i!=e;) {
		CAnalyzerList::iterator j(i++);	
		Analyzer& an = (Analyzer&)*j;
		if (!an.m_arStm[0] && !an.m_arStm[1])
			an.Delete();
	}


/*!!!
//!!!		Analyze(i);
	else
	{
		if (m_httpAnalyzerClass->TryRecognize(c))
			m_tcp2ans[c].push_back(CreateAnalyzer(m_httpAnalyzerClass,c));
		else
		{
			StreamMap::iterator j = m_recog.find(c);
			if( j == m_recog.end() )
				PreAnalyze(c);
			else
				Recognize(j);
		}
	}
	*/
}

/*!!!D
// Прекращение обработки потока и подчистка
// -------------

void ConnectionManager::DropConnection(TcpConnection *c)
{
	m_tcp2ans.erase(c);
//!!!	m_recog.erase(c);
	c->Delete();
}
*/

void ConnectionManager::FoundHole(TcpConnection *c) {
	TRC(2, "Hole found!");
//!!!	m_tcp2info.erase(c);
}

void ConnectionManager::ClosedConnection(TcpConnection *c) {
//!!!	TRC(1, "Stream end on " << /*!!!TcpStreamInfo(c).dump() <<*/ " in:" << c->GetInStream()->GetData().m_len << " out:" << c->GetOutStream()->GetData().m_len);
/*!!!D
	StreamMap::iterator i = m_tcp2ans.find(c);
	if (i != m_tcp2ans.end())
	{
		Analyzers &an_list = i->second;
		for(uint a=an_list.size(); a--;)
		{
			try
			{
				an_list[a]->Finalize(i->first->GetInStream()->GetData(), SERVER2CLIENT);
				an_list[a]->Finalize(i->first->GetOutStream()->GetData(), CLIENT2SERVER);
			}
			catch (RCExc)
			{
			}
		}
	}
	DropConnection(c);
	*/
}

/*!!!D
void ConnectionManager::ProcessHttpDialog(HttpDialog &dialog)
{
	TRC(1, "* Process HTTP Dialog Entry");
	for (int i=m_arClass.size(); i--;)
	{
		AnalyzerClassBase *cl = m_arClass[i];
		ptr<Analyzer> an = cl->CreateObject();
		String index = an->RecognizeHttpStream(dialog);
		if (index != "")
		{
			TRC(1, "* HTTP Dialog recognized by " << cl->GetName());
			if(m_http2an.find(index) == m_http2an.end())
				m_http2an[index] = an;
			m_http2an[index]->ProcessHttpDialog(dialog);
			TRC(1, "* HTTP Dialog processed by " << cl->GetName() << " with " << index);
			break;
		}
	}
};
*/

// Вывод всех карт Управлятора для отладки
// -------------

/*!!!
void ConnectionManager::DumpMap(StreamMap &map)
{
#ifdef _DEBUG
	StreamMap::iterator istm;
	for (istm=map.begin();istm!=map.end();istm++)
	{
		D_TRACE(TRCAT_P,1, "\nStream: " << TcpStreamInfo(istm->first).dump());
		D_TRACE(TRCAT_P,1, "Buffers: " << istm->first->GetInStream()->GetData().m_len << " " << istm->first->GetOutStream()->GetData().m_len );
		D_TRACE(TRCAT_P,1, "InStream:");
		D_TRACE(TRCAT_P,1,istm->first->GetInStream()->GetData());
		D_TRACE(TRCAT_P,1,"\nOutStream:");
		D_TRACE(TRCAT_P,1,istm->first->GetOutStream()->GetData());
		D_TRACE(TRCAT_P,1,endl);
		for (Analyzers::iterator an=istm->second.begin();an!=istm->second.end();an++)
		{
			D_TRACE(TRCAT_P,1,(*an)->m_class->GetName() << " state: " << (*an)->State(CLIENT2SERVER) << " " << (*an)->State(SERVER2CLIENT));
		}
	}
#endif
}
*/


Message::Message()
	:	Subject(nullptr)
	,	m_bPrint(true)
	,	Direction(Snif::Direction::Unknown)
{
	DateTime = ConnectionManager::I->m_dtLastPacket;
}

String Message::AsString(bool bPrintDate) {
	String from = From ? From->ToString() : nullptr,
      		to = To ? To->ToString() : nullptr;
	LocalDateTime ldt = DateTime.ToLocalTime();
	String r = (g_opt_PrintAsDateTime||bPrintDate) ? ldt.ToString() : ldt.ToString(VAR_TIMEVALUEONLY);
	r += "\t"+m_analyzerClass->m_name+":\t";
	if (!!from)
		r += from;
	r += " -> ";
	if (!!to)
		r += to+"\t";
	if (!!Subject)
		r += "Subj:\t" + Subject+"\t";
	else
		r += Text;
	return r;
}

#if UCFG_XML && UCFG_WIN32
// XXX !!! as blob
XmlNode Message::AsXML() {
	XmlDocument doc = new XmlDocument;
	XmlNode root = doc.AppendChild(doc.CreateElement("message"));
	XmlNode user = root.AppendChild(doc.CreateElement("from"));
	user.AppendChild(doc.CreateElement("id")).InnerText = From->Uid;
	user.AppendChild(doc.CreateElement("ip")).InnerText = From->ClientAddress.ToString();
	XmlNode peer = root.AppendChild(doc.CreateElement("to"));
	peer.AppendChild(doc.CreateElement("id")).InnerText = To->Uid;
	peer.AppendChild(doc.CreateElement("ip")).InnerText = To->ClientAddress.ToString();
	root.AppendChild(doc.CreateElement("timestamp")).InnerText = DateTime.ToString();
	root.AppendChild(doc.CreateElement("text")).InnerText = Text;
	return root;
}
#endif

void Message::SaveFrom() {
	if (!From)
		return;
	String suffix, data;
/*!!!		if (g_opt_message_as_xml)
	{
		data = AsXML().TransformNode(UserManager::I().MessageXslt);
		suffix = ".xml";
	}
	else */
		data = AsString(true);
#if UCFG_SNIF_PACKET_CAPTURE
	String path = Path::Combine(m_analyzerClass->Dir, From->ToDirName()+suffix);
#	if UCFG_USELISP
	CLispHelper::I().Call("MY-APPEND", path, data);
#	else
	ofstream ofs((const char*)path, ios::app);
	ofs << data << endl;
#	endif
#endif
}

void Message::SaveTo() {
	if (!To)
		return;
	String suffix, data;
		data = AsString(true);
#if UCFG_SNIF_PACKET_CAPTURE
	String path = Path::Combine(m_analyzerClass->Dir, To->ToDirName()+suffix);
#	if UCFG_USELISP
	CLispHelper::I().Call("MY-APPEND", path, data);
#	else
	ofstream ofs((const char*)path, ios::app);
	ofs << data << endl;
#	endif
#endif
}


void Message::Finish() {
	if (From && From->ClientAddress.IsEmpty())
		From->ClientAddress = ConnectionManager::I->m_lastSrcEndPoint.Address;
	if (To && To->ClientAddress.IsEmpty())
		To->ClientAddress = ConnectionManager::I->m_lastDstEndPoint.Address;

#ifdef _DEBUG//!!!D
	//Sleep(1000);
#endif

	if (Text == "")
		return;
	if (CTcpMan::s_bEnableLog && Text.Length < MAX_COUT_MESSAGE_LEN) {
		SaveFrom();
		SaveTo();
	}

#if UCFG_SNIF_USE_DB
	DbFinish();
#endif

	CMsganTcpMan::I->OnMessage(this);
}

/*!!!D
void Message::Process() {
	Finish();
}*/

FileTransfer::FileTransfer() {
	static bool s_bAlreadyWarn;
	if (!exchange(s_bAlreadyWarn, true) && CTcpMan::s_bEnableLog && !g_opt_SaveFiles)
		cerr << "Warning: File transfer detected, but \"File Save\" disabled, use option '-f'" << endl;
}

/*!!!D
void GetStreamRest(CBlobReadStream &stm, Blob &rest)
{
	int pos = (int)stm.Position;
	int size = (int)stm.Size;
	rest = Blob(0, size-pos);
	stm.ReadBuffer(rest.Data, rest.Size);
};
*/

CMessageAnalyzer::CMessageAnalyzer(ptr<AnalyzerClassBase> cl0, ptr<AnalyzerClassBase> cl1)
	:	m_cl0(cl0)
	,	m_cl1(cl1)
{
}


CMessageAnalyzer::~CMessageAnalyzer() {
}

void CMessageAnalyzer::Deactivate() {
	ConnectionManager::I->m_setActivatedAnalyzers.erase(this);
}



int g_codepage;
bool g_bEncChanged;
Encoding *g_encMessage = &Encoding::Default();

CMsganTcpMan *CMsganTcpMan::I;


bool CMsganTcpMan::ProcessOption(char opt, const char *optarg) {
	switch (opt) {
		case 'V':
			CTrace::s_nLevel++;
			return true;
		case 'W':
			CTrace::s_pOstream = new ofstream(optarg, ios::binary);//!!!D
			return true;
		case 'z':
			g_opt_findbyip = true;
			return true;
		case 'w':
			g_opt_write_traffic = true;
			return true;
		case 'x':
			g_opt_message_as_xml = true;
			return true;
		case 'n':
			g_opt_ResolveEnabled = false;
			return true;
		case 'P':
			{
				String aName = optarg,
						    uname = aName.ToUpper();
				if (uname == "ALL")
					for (CMessageAnalyzerClass::CByNameMap::iterator i=CMessageAnalyzerClass::ByNameMap().begin(), e=CMessageAnalyzerClass::ByNameMap().end(); i!=e; ++i)
						m_cm.m_classesToLoad.insert(i->first);
				else if (CMessageAnalyzerClass::ByNameMap().find(uname.ToUpper()) == CMessageAnalyzerClass::ByNameMap().end())
					cerr << "Unknown protocol: " << aName << endl;
				else
					m_cm.m_classesToLoad.insert(uname.ToUpper());
			}
			return true;
		case 'E':
			m_cm.MailboxFormat = String(optarg).ToUpper();
			return true;
#ifdef WIN32
		case 'e':
			{
				String cp = String(optarg).ToUpper();
				if (cp == "ANSI")
					g_codepage = CP_ACP;
				else if (cp == "OEM")
					g_codepage = GetOEMCP();
				else if (cp == "UTF8")
					g_codepage = CP_UTF8;
				else if (cp == "UNICODE")
					g_codepage = CODEPAGE_UNICODE;
				else
					g_codepage = atoi(cp);
			}
			return true;
#endif
		case 'f':
			g_opt_SaveFiles = true;
			return true;			
		case 'm':
			{
				g_bEncChanged = true;
				if (int cp = atoi(optarg))
					g_encMessage = Encoding::GetEncoding(cp);
				else
					g_encMessage = Encoding::GetEncoding(optarg);
			}
			return true;

#if UCFG_SNIF_PACKET_CAPTURE
		case 'l':
			Directory::CreateDirectory(CProtoEng::s_pMain->m_sLogDir = optarg);
			return true;
#endif
	}
	return false; 
}

CMsganTcpMan::CMsganTcpMan() {
	I = this;
#if UCFG_SNIF_PACKET_CAPTURE
	m_options += "Be:fm:nE:l:VW:P:qwxz";
#endif
}

CMsganTcpMan::~CMsganTcpMan() { 
	I = 0;
#if UCFG_SNIF_PACKET_CAPTURE && !UCFG_SNIF_USE_PCAP
	WpcapCloseAll();
#endif
}

#if UCFG_SNIF_PACKET_CAPTURE

String __stdcall CMsganTcpMan::GetDefaultDbConnstr() {
	return Path::Combine(CProtoEng::s_pMain->m_sLogDir, "icqsnif.db");
//!!!	return "Provider=Microsoft.Jet.OLEDB.4.0;Data Source="+Path::Combine(CProtoEng::s_pMain->m_sLogDir, "icqsnif.mdb");
}
#endif

void CMsganTcpMan::OnMessage(Message *message) {
	if (message->m_bPrint) {
		if (!g_opt_PrintAsDateTime) {
			static DateTime s_datePrev;
			DateTime dt = message->DateTime.Date;
			if (dt != s_datePrev) {
				s_datePrev = dt;
				PLogMessage("# " + s_datePrev.ToString(VAR_DATEVALUEONLY));
			}
		}
		PLogMessage(message->AsString());
	}
}

void CMsganTcpMan::OnUser(User *user) {
	user->Log();
	user->Users->Save();
}


static regex s_reHtmlTags("<[^>]*>");

String HtmlToPlain(RCString s) {
	Blob blob = Encoding::UTF8.GetBytes(s);
	string s1 = regex_replace(string((const char*)blob.constData(), blob.Size), s_reHtmlTags, string(" "));
	return Encoding::UTF8.GetChars(ConstBuf(s1.data(), s1.size()));
}

} // Snif::

