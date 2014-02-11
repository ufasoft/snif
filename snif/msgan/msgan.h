/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#pragma once

#include "tcpapi.h"

#if UCFG_SNIF_USE_DB
#	include <el/db/ext-sqlite.h>
using namespace Ext::DB;
using namespace Ext::DB::sqlite3_NS;
#endif

#if UCFG_SNIF_USE_OLEDB
#	include <el/db/ext-oledb.h>
#endif	

#undef _WINNLS_
#undef NONLS
//!!!#include <WinNls.h>

#if UCFG_LIB_DECLS
#	ifdef MSGAN
#		define MSGAN_CLASS       AFX_CLASS_EXPORT
#	else
#		pragma comment(lib, "msgan")
#		define MSGAN_CLASS       AFX_CLASS_IMPORT
#	endif
#else
	#define MSGAN_CLASS
#endif

#include "params.h"
#include "snif-config.h"

namespace Snif {

extern MSGAN_CLASS CTraceCategory TRCAT_P;
extern MSGAN_CLASS CTraceCategory TRCAT_UM;
extern MSGAN_CLASS CTraceCategory TRCAT_HTTP;

class User;
}

namespace Ext {
template <> struct ptr_traits<Snif::User> {
	typedef Interlocked interlocked_policy;
};
} // ::Ext

class Nuint16_t {
	uint16_t m_val;
public:
	operator uint16_t() const { return ntohs(m_val); }
};


namespace Snif {


class Message;
class UserManager;
class CMessageAnalyzerClass;
class CConnectionInfo;
class Analyzer;
class AnalyzerStream;

class CMessageAnalyzer;
class AnalyzerClassBase;
class HttpAnalyzerClass;

typedef multimap<int, AnalyzerClassBase*> Cpriority2anclassMultimap;

int LookForPattern(const ConstBuf &buf, const ConstBuf &pat);
uint skipnl(ConstBuf &buf);
bool ReadString(String& str, ConstBuf &buf);
//!!!void GetStreamRest(CBlobReadStream &stm, Blob &rest);

enum AnalyzerState {
	ASTATE_INITIAL,			// Начальное состояние обработчика
	ASTATE_OK,
	ASTATE_NEED_MORE,		// Нужны еще данные
//!!!	ASTATE_BadStream,	// Отказ от обработки соедиения
	ASTATE_NO_NEED, //!!!NoNeed = BadStream,
	ASTATE_NEED_MATCH,	// Ожидаем совпадения с подстрокой
	ASTATE_ASIS				// Обработка как есть
};

class StreamClient;

}
namespace Ext {
template <> struct ptr_traits<Snif::StreamClient> {
	typedef NonInterlocked interlocked_policy;
};
} // Ext::

namespace Snif {

class AnalyzerStream : public Object {
public:
	Analyzer *m_analyzer;
	CPointer<class StreamClient> StreamClient;
	CBool IsOut;

	size_t m_wanted;
	size_t m_processed;		// Processed bytes in each direction
	AnalyzerState m_state;
	int m_rstage;
	CInt<UInt64> m_offset;
	ConstBuf m_matchPattern;

	AnalyzerStream *Prev, *Next;

	AnalyzerStream();
	~AnalyzerStream();	
	void SetStreamClient(Snif::StreamClient *sc);
	void EnsureIncoming();
	void EnsureOutgoing();

	ConstBuf GetData();
	void Skip(size_t n);
	virtual void Process(const ConstBuf& mb) { m_processed = mb.Size; }
	void Process();
};

class StreamClient : public Object {
public:
	CInt<UInt64> m_offset;
	Blob m_blob;
	CConnectionInfo *m_ci;
	bool m_dir;

	typedef IntrusiveList<AnalyzerStream> CAnalyzerStreams;
	CAnalyzerStreams AnalyzerStreams;

	StreamClient(CConnectionInfo *ci, bool dir)
		:	m_ci(ci)
		,	m_dir(dir)
	{}

	void Unbind(AnalyzerStream *as);
	void Adjust();
};

struct AnalyzerListHook {
	AnalyzerListHook *Prev, *Next;
};

class Analyzer : public Object, public AnalyzerListHook {
protected:
	CBool m_bSwapped;
public:
	ptr<Analyzer> m_ptrSelf;

	CPointer<AnalyzerClassBase> m_class;
	CBool m_bRecognitionTryed;
	CBool m_bDeleted,
				m_bCaptured;
	CPointer<CConnectionInfo> m_ci;

	Analyzer *Prev, *Next;

//!!!	PotentialAnalyzers::iterator m_iterator;

//!!!	ptr<TcpConnection> m_cTcp;	// Текущее соединение	
//!!!	TcpStreamInfo m_info;
	ptr<User, Interlocked> m_user;				// Current User
	CPointer<Message> m_msg;				// Current Message
	CBool m_newan;
#ifdef _DEBUG
	uint m_id;		// Unique handler ID > 0
	int m_cnt;
#endif

	AnalyzerStream *m_arStm[2];

	Analyzer();
	~Analyzer();
	virtual void Finish() {}

	void SetOutStm(AnalyzerStream *stm) { 
		(m_arStm[0] = stm)->IsOut = true;
		stm->m_analyzer = this;
	}

	void SetInStm(AnalyzerStream *stm){
		(m_arStm[1] = stm)->m_analyzer = this;
	}

	void SwapStreams();
	void Capture();
	void Delete();
	virtual bool TryRecognize() { return false; }
	virtual void OverflowProtection();
//!!!	virtual void Process(const ConstBuf& data, uint direction) {}		// Собственно обработчик
//!!!	virtual void Recognize(const ConstBuf& data, uint direction ) {}	//!!! Распознование потока
	virtual void Finalize(const ConstBuf& data, uint direction) {}; // Завершение потока

//!!!	uint RState(uint dir) const { return m_rstate[dir]; }			// Состояние распозновалки

	/*!!!
	typedef pair< ptr<StreamCondition>, ptr<Analyzer> > ConditionalAnalyzer;
	bool IsNewStream() const { return m_newan; }
	virtual ConditionalAnalyzer NewAnalyzer() { m_newan=false; return ConditionalAnalyzer(new PortCondition(0), this); }
	*/


friend class AnalyzerClassBase;
friend class ConnectionManager;
};

} namespace Ext {
template <> struct ptr_traits<Snif::AnalyzerClassBase> {
	typedef NonInterlocked interlocked_policy;
};
} // Ext::
namespace Snif {

class MSGAN_CLASS CMessageAnalyzer : public Object {
public:
	ptr<AnalyzerClassBase> m_cl0,
							m_cl1;
//!!!	auto_ptr<CTcpAnalyzer> m_tcpAn;

	CMessageAnalyzer(ptr<AnalyzerClassBase> cl0, ptr<AnalyzerClassBase> cl1 = nullptr);

	/*!!!
	CMessageAnalyzer(CTcpAnalyzer *tcpAn)
		:	m_tcpAn(tcpAn)
	{}*/

	virtual ~CMessageAnalyzer();
	void Deactivate();
};

class MSGAN_CLASS UserManager {
//!!!	static UserManager *s_pI;
public:
	typedef map<IPAddress, ptr<User> > TIPUserMap;
private:
	mutex m_cs;
	vector<ptr<User> > m_arUser;
	TIPUserMap m_mIp2User;
//!!!R	static Regex s_reDb;
	CBool m_bLoaded;
	DateTime m_dtLastSave;
public:
//!!!	XmlDocument MessageXslt;
	CMessageAnalyzerClass& m_analyzerClass;

	void Load();
	void Save();
	void SaveToDb();

	UserManager(CMessageAnalyzerClass& analyzerClass)
		:	m_analyzerClass(analyzerClass)
	{}

	~UserManager();
//!!!	static UserManager& I() {	return *s_pI; }
	User *FindUserByIP(const IPAddress& ip);
	User *FindUserByID(RCString uid, const IPAddress& ip=IPAddress());
	User *FindUserByNick(RCString uid, const IPAddress& ip=IPAddress());
	ptr<User> GetByNick(RCString nick);
	ptr<User> GetByClientAddress(const IPAddress& ha);
	ptr<User> FindUserByPhone(RCString phone);
	ptr<User> GetByServerLogin(const IPEndPoint& server, RCString login);

	void AddInitial(User *u);
	ptr<User> Add(User *u);
	void AddMapping(const IPAddress& ip, User *u);

#ifdef _X_DEBUG
	void DumpList();
	vector<ptr<User> > GetUsers() { return m_arUser; }
#endif
};

typedef IntrusiveList<Analyzer> AnalyzerObjects;

class AnalyzerClassBase : public Object {
	Cpriority2anclassMultimap::iterator m_i;
protected:
	uint m_id;
	ptr<Analyzer> Insert(Analyzer *an);
public:
	String m_name;
	int Priority;

	AnalyzerClassBase();
	~AnalyzerClassBase();
	void Create(RCString name);
	virtual ptr<Analyzer> CreateObject() =0;
	String GetName() { return m_name; }

	virtual void InThreadExecute() {}

	AnalyzerObjects m_objects;
};

template <class T> class AnalyzerClass : public AnalyzerClassBase {
public:
	ptr<Analyzer> CreateObject() { return Insert(new T); }
};

class User : public Object {
	typedef User class_type;
public:
	typedef Interlocked interlocked_policy;

	CBool Dirty;
	
	CPointer<UserManager> Users;

	LONG m_dbID;

	String FirstName, LastName;
	String Email;
	String MobilePhone;
	IPAddress ClientAddress;
	IPEndPoint Server;

	typedef map<IPAddress, bool> TIPMap;
//!!!	UInt32 ccip;		// current client ip
	IPAddress csip;		// current server ip
	TIPMap m_server_ip;

	User()
		:	m_dbID(0)
		,	m_nick(nullptr)
	{
	}

	void SaveToDB();
	LONG AddNewToDB();
	Int32 GetDBID();

	String get_Uid() { return m_uid; }	
	void put_Uid(RCString v) {
		m_uid = v;
		Dirty = true;
	}
	DEFPROP(String, Uid);

	String get_Nick() { return !m_nick ? "" : m_nick; }	
	void put_Nick(RCString v) {
		m_nick = v;
		Dirty = true;
	}
	DEFPROP(String, Nick);

	String get_Password() { return m_password; }	
	void put_Password(RCString v) {
		m_password = v;
		Dirty = true;
	}
	DEFPROP(String, Password);

	virtual void PostLoad() {}
	virtual Message* NewMessage(const DateTime &dt) { return 0; };
//	virtual Message* NewMessage(const DateTime &dt, User *m_peer)=0;
	virtual void Finish(Message *) {};

	friend class UserManager;
	
//!!!	void AddNickname(RCString nick);
	void AddClientIP(const IPAddress& ip);
	void AddServerIP(const IPAddress& ip);
	void Log();
	void SetPassword(RCString s);

	static User *FindByID(const char *uid);

	static String AFXAPI ReplaceDisabledChars(RCString s);
	String ToString();	
	virtual String ToDirName();
	IPAddress server_ip() { return csip; }
//!!!	UInt32 client_ip() { return ccip; }
private:
	String m_uid;
	String m_nick;
	String m_password;
};


/*
smtp:
	id: from_email, nick: from_alias, server_ip, password (smtp auth ?)
pop3:
	id: username, nick: To:[.*], password: pop3 pass, server_ip, client_ip
irc:
	id: hostmask, nick: irc_nick, password: ?, server_ip, client_ip
icq:
	id: uin, nick: nick, password: icq_password, server_ip, client_ip
msn:
	id: msn_id, nick: msn screen name, msn_password, server_ip, client_ip
*/

enum EAnalyzerType
{
	ATYPE_OPTIONAL,
	ATYPE_MANDATORY,
	ATYPE_NON_DEFAULT
};

class CMessageAnalyzerClass {
public:
	typedef CMessageAnalyzerClass class_type;

	String m_name;
	EAnalyzerType Type;
	CBool m_bActive;
	UserManager Users;
	LONG m_dbID;

	typedef map<String, CMessageAnalyzerClass*> CByNameMap;
	MSGAN_CLASS DECLSPEC_NOINLINE static CByNameMap& AFXAPI ByNameMap(); //!!! {			// to prevent multiple static instances
//!!!		static CByNameMap s_t;
//!!!		return s_t;
//!!!	}

#if UCFG_SNIF_PACKET_CAPTURE
	String get_Dir() {
		String dir = Path::Combine(CProtoEng::s_pMain->m_sLogDir, m_name);
		Directory::CreateDirectory(dir);
		return dir;
	}
	DEFPROP_GET(String, Dir);
#endif

	CMessageAnalyzerClass(RCString name);
	virtual ~CMessageAnalyzerClass() {}
	virtual CMessageAnalyzer *CreateObject() =0;	
	MSGAN_CLASS CMessageAnalyzer *Activate();
	virtual ptr<User> CreateUser();
	virtual bool Execute() { return false; }
	virtual void Finalize() {}
private:
	void DbActivate();
};

typedef IntrusiveList<AnalyzerListHook> CAnalyzerList;

class CConnectionInfo : public TcpConnection {
public:
	CPointer<StreamClient> Clients[2];
	
	CAnalyzerList Analyzers, PotentialAnalyzers;

	IPEndPoint DstEndPoint,
						SrcEndPoint;
//!!!R	class TcpConnection *TcpConnection;

	int Priority;

	CConnectionInfo()
		:	Priority(0)
		,	m_client0(this, false)
		,	m_client1(this, true)
	{}

	~CConnectionInfo();

	void SwapStreams();
	bool TrySwapStreams();
	void Add(Analyzer *a, bool bAtEnd = false);
	void ReleaseAllAnalyzers();
	void Update();
	void ProcessStream(int dir);
private:
	StreamClient m_client0, m_client1;
};

//!!!R typedef unordered_map<ptr<TcpConnection>, CConnectionInfo> CTcp2Info;

class Tasklet : public Object {
public:
	typedef Interlocked interlocked_policy;

	CEvent EvComplete;

	virtual void Execute() {}
};

/*!!!
namespace Ext {
	template <> struct ptr_traits<Tasklet::HierarchyId> {
	typedef Interlocked interlocked_policy;
};
} // Ext::
*/



#if UCFG_SNIF_USE_DB

class DbThread : public Thread {
	typedef Thread base;
public:
	CBool Enabled, Failed;
	CBool m_bSqlite;
	queue<ptr<Tasklet> > Queue;
	mutex m_csQueue;

	SqliteConnection m_sqlite;
#if UCFG_SNIF_USE_OLEDB
	OleDbConnection m_db;
	ADODB::_RecordsetPtr m_rsUsers, m_rsMessages;
#endif

	DbThread();
	
	~DbThread() {
	}

	bool Enqueue(Tasklet *tasklet);
protected:
	CEvent m_ev;
	String ConnString;
	CBool m_dbTxBegin;

	void OpenDatabase();
	void CreateDatabase();
	void EnsureTransactionStarted();
	void CommitTransactionIfStarted();
	void Execute() override;

	void Stop() {
		base::Stop();
		m_ev.Set();
	}
};

#endif


class MSGAN_CLASS ConnectionManager : public CTcpAnalyzer {
	typedef CTcpAnalyzer base;

//!!!S	ptr<Analyzer> ConnectionManager::CreateAnalyzer(AnalyzerClassBase *cl, TcpConnection *c);
public:
	CThreadRef m_tr;
	String MailboxFormat;
	DateTime m_dtLastPacket;
	IPEndPoint m_lastSrcEndPoint, m_lastDstEndPoint;
	set<String> m_classesToLoad;
	static bool s_bEnableWebActivity;
	mutex MtxAnalyzerClasses;

#if UCFG_SNIF_USE_DB
	ptr<Snif::DbThread> DbThread;
#endif

	typedef set<ptr<CMessageAnalyzer> > CActivatedAnalyzers;
	CActivatedAnalyzers m_setActivatedAnalyzers;

//!!!	typedef vector<ptr<Analyzer> > Analyzers;
//!!!D	typedef map<ptr<TcpConnection>, Analyzers > StreamMap;
//!!!R	CTcp2Info m_tcp2info;
	Cpriority2anclassMultimap m_priority2anclass;

//!!!	StreamMap m_recog;
//!!!	HttpMap m_http2an;

//!!!	ptr<HttpAnalyzerClass> m_httpAnalyzerClass;

	vector<AnalyzerClassBase*> m_arClass;
	static ConnectionManager *I;

	void LogHttpRequest(DateTime &dt, RCString, RCString);
	
	ConnectionManager();
	~ConnectionManager();
	static void AFXAPI CloseAll();	
	void Start(bool bStartIfEmpty = true);
//!!!	void PreAnalyze(TcpConnection *c);
//!!!	void Recognize( StreamMap::iterator irec );
//!!!	void Analyze(StreamMap::iterator istm);

//!!!	void ProcessHttpDialog(HttpDialog &dialog);

//!!!	bool do_matchrecog( ptr<Analyzer> an, ConstBuf buf, uint dir );
	/*!!!
	bool do_wantedmatch( ptr<Analyzer> an, TcpStream *stm, uint dir );	
	void DoProcess(Analyzer *an, TcpStream *stm, uint dir)
	{
		an->Process(stm->GetData(), dir);
		stm->Skip(an->m_processed[dir]);
	}*/

	ptr<TcpConnection> CreateTcpConnectionObject(CTcpMan& tcpMan, ITcpConnection *conn);
	void CreatedConnection(TcpConnection *c) override;
	void UpdatedConnection(TcpConnection *c) override;
	void FoundHole(TcpConnection *c) override;
	void ClosedConnection(TcpConnection *c) override;
	
//!!!	void DumpMap(StreamMap &map);
//!!!	void DropConnection(TcpConnection *c);

	class ParallelThread : public Thread {
	public:
		ParallelThread()
			:	Thread(&ConnectionManager::I->m_tr)
		{}
	private:
		void Execute() override;
	};

	ptr<ParallelThread> m_parallelThread;

friend class AnalyzerClassBase;	
};


/*!!!
class HttpMessage
{
	typedef map<String, String> StringMap;
	StringMap m_header;
	StringMap m_uri;

	Blob m_content;
	String m_uri_full;
	String m_uri_base;

	static Regex sre_req;
public:
	DateTime m_dt;

	String Uri(RCString part)
	{
		StringMap::const_iterator test = m_uri.find(part);
		if( test != m_uri.end() )
			return test->second;
		else
			return "";
	}
	
	String UriBase() { return m_uri_base; }
	
	const ConstBuf Content() const
	{
		return m_content;
	}
};
*/

class HttpDialog {
public:
	CHttpRequest Request;
	CHttpResponse Response;
	CConnectionInfo *m_ci;
};

class HttpAnalyzerStream : public AnalyzerStream {
public:
	CHttpHeader *HttpHeader;

	void Process(const ConstBuf& data) override;
protected:
	UInt64 m_nToSkip;

	void AfterMessage();
};

class OutHttpAnalyzerStream : public HttpAnalyzerStream {
	void Process(const ConstBuf& data) override;
public:
	OutHttpAnalyzerStream() {
		m_wanted = 4;
		m_state = ASTATE_NEED_MORE;
	}
};

class InHttpAnalyzerStream : public HttpAnalyzerStream {
	void Process(const ConstBuf& data) override;
public:
	InHttpAnalyzerStream() {
		m_wanted = 4;
		m_rstage = -1;
		m_state = ASTATE_NEED_MORE;
	}
};

class HttpAnalyzer : public Analyzer {
public:
	CHttpRequest Request;
	CHttpResponse Response;

	OutHttpAnalyzerStream m_outStm;
	InHttpAnalyzerStream m_inStm;

	HttpAnalyzer();
	void Finish();
	bool TryRecognize() override;
	void AfterResponse();
	void ProcessSubscribers();
};

class HttpSubscription {
public:
	HttpSubscription();
	virtual ~HttpSubscription();
	virtual void OnReceived(HttpDialog *d) =0;
};

class HttpAnalyzerClass : public AnalyzerClass<HttpAnalyzer> {
public:
	static HttpAnalyzerClass *I;
	CSubscriber<HttpSubscription> m_subscriber;

	HttpAnalyzerClass() {
		I = this;
		Priority = 1; 
		Create("HTTP");
	}

	~HttpAnalyzerClass() 	{
		I = 0;
	}
};

inline HttpSubscription::HttpSubscription() {
	if (HttpAnalyzerClass::I)
		HttpAnalyzerClass::I->m_subscriber += this;
}

inline HttpSubscription::~HttpSubscription() {
	if (HttpAnalyzerClass::I)
		HttpAnalyzerClass::I->m_subscriber -= this;
}

typedef ConstBuf AString; //!!! we need AsciiString because we don't know encoding
typedef const AString& RAString; //!!! we need AsciiString because we don't know encoding

class Message : public Object {
public:
	typedef Interlocked interlocked_policy;

	CBool m_bPrint;
	class DateTime DateTime;

	String Text;
	String Subject;
	ptr<User> From, To;
	CPointer<CMessageAnalyzerClass> m_analyzerClass;
	Snif::Direction Direction;

	Message();
	virtual void Finish();
	virtual String AsString(bool bPrintDate = false);
#if UCFG_XML && UCFG_WIN32
	virtual XmlNode AsXML();
#endif

	void SwapPeers() { swap(From, To); }

	/*!!!
	void OneLine(RCString line)
	{
		AddLine(line);
		Finish();
	}*/
protected:
	virtual void SaveFrom();
	virtual void SaveTo();
	void DbFinish();	
};

class WebMessage : public Message {
	typedef Message base;
public:
	IPAddress ClientAddress;
	String Host;

	WebMessage();
	void Finish();
};

class FileTransfer {
public:
	FileTransfer();
};

class WebUser : public User {
public:
	WebUser();
	static WebUser *GetByServerLogin(const IPEndPoint& server, RCString login);
	static WebUser *GetByClientAddress(const IPAddress& ha);
};

typedef void (AFXAPI* PFNLogMessage)(RCString s);

extern MSGAN_CLASS PFNLogMessage PLogMessage;
void LruLogMessage(RCString s);

extern MSGAN_CLASS bool g_opt_findbyip,
						g_opt_write_traffic,
						g_opt_message_as_xml,
						g_opt_ResolveEnabled,
						g_opt_SaveFiles;


class LineAnalyzerStream : public AnalyzerStream {
public:
	CBool BinaryMode;
	size_t m_defaultWanted;
protected:
	virtual void ProcessLine(const AString& line) {}
	virtual void ProcessBinary(const ConstBuf& data) {}
	void Process(const ConstBuf& data) override;
	
	LineAnalyzerStream(size_t defaultWanted = 4)
		:	m_defaultWanted(defaultWanted)
	{
		m_wanted = m_defaultWanted;
		m_state = ASTATE_NEED_MORE;
	}
};

class CMessageItem : public pair<pair<ptr<User>, ptr<User> >, String> {
public:
	mutable int AnalyzerID;

	CMessageItem(ptr<User> from, ptr<User> to, RCString smsg)
		:	pair<pair<ptr<User>, ptr<User> >, String>(make_pair(make_pair(from, to), smsg))
	{}
};

} namespace EXT_HASH_VALUE_NS {
inline size_t hash_value(const Snif::CMessageItem& mi) {
    return hash<ptr<Snif::User> >()(mi.first.first)+hash<ptr<Snif::User> >()(mi.first.second)+hash<String>()(mi.second);
}
}
EXT_DEF_HASH(Snif::CMessageItem)

namespace Snif {

class MSGAN_CLASS CMsganTcpMan : public CTcpMan {
	bool ProcessOption(char opt, const char *optarg);
public:
	static CMsganTcpMan *I;

	ConnectionManager m_cm;

	CMsganTcpMan();
	~CMsganTcpMan();

	static String __stdcall GetDefaultDbConnstr();
	virtual void OnMessage(Message *message);
	virtual void OnUser(User *user);
};

const int CODEPAGE_UNICODE = -1;
extern MSGAN_CLASS int g_codepage;
extern bool g_bEncChanged;
extern MSGAN_CLASS Encoding *g_encMessage;

String HtmlToPlain(RCString s);

} // Snif::
