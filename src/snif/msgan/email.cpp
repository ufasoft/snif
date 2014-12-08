/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>
#include <fcntl.h>

#include "msgan.h"

namespace Snif {


#pragma pack(push, 1)

struct STOCHeader
{
	DWORD Version1;
	DWORD Version2;
	char  Name[32];
	WORD	Type;
	DWORD	Unk1;
	DWORD Unk2;
	DWORD	Unk3;
	DWORD UnkFF1;	// ff
	DWORD UnkFF2;
	DWORD UnkFF3;
	DWORD UnkFF4;
	WORD	Unk4;	// 2
	WORD	Unk5;	// 1
	BYTE	Unk[28];
	WORD	Number;

	STOCHeader()
	{
		UnkFF1 = UnkFF2 = UnkFF3 = UnkFF4 = DWORD(-1);
		Unk4 = 2;
		Unk5 = 1;
		Version1 = 0x30;
	}
};

struct STOCMsg
{
	DWORD	Offset;
	DWORD	Length;
	DWORD	DateTime;
	WORD	Status;
	BYTE	Options1;
	BYTE	Options2;
	WORD	Priority;
	char	TimeStamp[32];
	char	From[64];
	char	Subject[64];
	DWORD	CoordX;
	DWORD	CoordY;
	char	Pad[32];

	STOCMsg()
	{
		ZeroStruct(_self);
		CoordX = DWORD(-1);
		CoordY = DWORD(-1);
	}
};

#pragma pack(pop)




/*!!!

EmailMessage::EmailMessage(User *u, const DateTime &dt, uint subproto)
	: Message(u, dt, "", "" ), m_once(true)
{
	m_network = String("email");
	String srv = u->server_ip().ToString();
	String clnt = "email." + u->client_ip().ToString();
	String box = "Inbox";
	if ( subproto == 1)
		box = "Outbox";
	String basepath = Path::Combine(Path::Combine(CProtoEng::s_pMain->m_sLogDir, clnt), srv);
	m_writer = CreateEudoraWriter(basepath, box);
}

*/

static regex s_reReplaceNum(":\\d+");

class EmailUser : public User {
	typedef User base;
public:
	EmailUser();

	EmailUser(RCString s) {
		Email = s;
	}

	String ToDirName() override {
		String n = !!get_Nick() ? Nick : Email;
		String s = !n.IsEmpty() ? ReplaceDisabledChars(n) : "Unknown";
		String host = Server.ToString();
#if UCFG_SNIF_HOST_RESOLVE
		if (g_opt_ResolveEnabled)
			host = CHostResolver::Resolve(Server);
#endif
		Blob blob = Encoding::UTF8.GetBytes(host);
		string s1 = regex_replace(string((const char*)blob.constData(), blob.Size), s_reReplaceNum, string(""));
		String serv = Encoding::UTF8.GetChars(ConstBuf(s1.data(), s1.size()));
		if (Server.Port != 110)
			serv += "_"+Convert::ToString(Server.Port);
		return s+"@"+serv;
	}

	static EmailUser *FindByServerLogin(const IPEndPoint& server, RCString login);
	static EmailUser *GetByClientAddress(const IPAddress& ha);
};

static wregex s_reMimeSubj(String("=\\?(.*?)\\?B\\?(.*?)\\?=(.*)$"));

class EmailWriter : public Message {
public:
	String m_directory;

	EmailWriter();

	virtual void Create() {
	}

	virtual void AddHeaderLine(RAString line) {
	}

	virtual void AddBodyLine(RAString line) {
	}

	virtual void AfterHeader() {
	}

	String DecodeEmailHeader(RCString header) {
		Smatch m;
		if (regex_search(header, m, s_reMimeSubj)) {
			Blob blob = Convert::FromBase64String(m[2]);
			return String((const char*)blob.constData(), blob.Size)+m[3].str();
		}
		return header;
	}

	String DecodeField(CHttpHeader& header, RCString name) {
		String s = header.Headers.Get(name);
		if (!!s)
			return DecodeEmailHeader(s);
		return s;
	}

	void Finish() {
		CHttpHeader header;
		header.ParseHeader(ReadHttpHeader(StringInputStream(Text)), true, true); //!!!
		From = new EmailUser(DecodeField(header, "From"));

		String s = DecodeField(header, "To");
		if (s.IsEmpty()) {
			CStringVector ar = header.Headers.GetValues("Received");
			for (int i=0; i<ar.size(); ++i) {
				String h = ar[i];
				static wregex reReceived(String("for ([^;]+);"));
				Smatch m;				
				if (regex_search(h, m, reReceived)) {
					s = m[1];
					break;
				}
			}
		}
		To = new EmailUser(s);
		Subject = DecodeField(header, "Subject");
		Message::Finish();
	}

	virtual void ExtraAddLine(RAString line) {
		DWORD emailMaxSize = EMAIL_MAX_SIZE;
#if UCFG_EXTENDED
		emailMaxSize = RegistryKey(AfxGetCApp()->KeyCU, "Options").TryQueryValue("EmailMaxSize", emailMaxSize);
#endif
		if (Text.Length < emailMaxSize)
			Text += String((const char*)line.P, line.Size)+"\n";
	};
};

class FileEmailWriter : public EmailWriter {
public:
	static set<String> s_setFiles;
	
	String m_filename;
	unique_ptr<ofstream> m_mail;	// Where messages go

	~FileEmailWriter() {
		s_setFiles.erase(m_filename);
	}

	void AddHeaderLine(RAString line);
	void AddBodyLine(RAString line);	
};

set<String> FileEmailWriter::s_setFiles;

void FileEmailWriter::AddHeaderLine(RAString line) {
	EmailWriter::AddHeaderLine(line);
	if (m_mail.get()) {
		m_mail->write((const char*)line.P, line.Size);
		*m_mail << endl;	
	}
	ExtraAddLine(line);
}

void FileEmailWriter::AddBodyLine(RAString line) {
	if (m_mail.get()) {
		if (line.Size>=5 && !memcmp(line.P, "From ", 5))  // for UNIX mailbox
			*m_mail << ">";
		m_mail->write((const char*)line.P, line.Size);
		*m_mail << endl;	
	}
	ExtraAddLine(line);
}

class EudoraWriter : public FileEmailWriter {
	size_t m_written,		// bytes already written to 
	       m_offset;		// current mailbox offset
	STOCHeader m_hdr;
	String mTocPath;
public:
	EudoraWriter()
		: m_written(0),
		  m_offset(0)
	{}

	void Create()
	{
		String box = "eudora";
		String eu_mail = Path::Combine(m_directory, box+".mbx");
		mTocPath = Path::Combine(m_directory, box+".toc");
		if (FileInfo(mTocPath)) {
			// Читаем TOC заголовок из файла
			ifstream toc((const char*)mTocPath, ios::binary);
			toc.read((char *) &m_hdr, sizeof(STOCHeader));
		} else {
			// Создаем TOC по новой
			ofstream((const char*)mTocPath, ios::app | ios::binary);
			strncpy(m_hdr.Name, box, 31);
			ofstream desc((const char*)Path::Combine(m_directory, "descmap.pce"), ios::app);
			desc << box << "," << box << ".mbx" << ",S,N" << endl;
		}
		// Streams
		// XXX: check creaction failure
		m_mail.reset(new ofstream((const char*)eu_mail, ios::app | ios::binary));
	}
	
	void ExtraAddLine(RAString line) {
		m_written += line.Size + 1; // endl
	}
	
	void Finish() {
		STOCMsg m;
		m.Offset = (DWORD)m_offset;	// size of MBX
		m.Length = (DWORD)m_written;
		strncpy(m.Subject, Subject, 63);
		strncpy(m.From, From->Email, 63);		
		m_hdr.Number++;

		ofstream ofs((const char*)mTocPath, ios::binary|ios::in);
		ofs.write((const char *)&m_hdr, sizeof(STOCHeader));
		ofs.seekp(0, ios::end);
		ofs.write((const char *)&m, sizeof(STOCMsg));
	}
};


class UnixWriter : public FileEmailWriter {
public:
	void Create() {
		for (int i=0;; i++) {			//!! to avoid locked files
			String filename = Path::Combine(m_directory, "unix"+(i ? Convert::ToString(i) : "")+".mbx");
			if (s_setFiles.insert(filename).second) {
				m_mail.reset(new ofstream((const char*)(m_filename=filename), ios::app | ios::binary));
				break;		
			}			
		}
		tm tmLastPacket = ConnectionManager::I->m_dtLastPacket;
		*m_mail << "From icqsnif " << asctime(&tmLastPacket);
	}

	void Finish() {
		*m_mail << endl;
		m_mail = 0;
		EmailWriter::Finish();
	}
};

class MemUnixWriter : public EmailWriter {
	MemoryStream m_qs;

	void Create() {
		tm tmLastPacket = ConnectionManager::I->m_dtLastPacket;
		String first = String("From icqsnif ") + asctime(&tmLastPacket);
		m_qs.WriteBuffer((const char*)first, first.Length);
	}

	void AddHeaderLine(RAString line) {
		EmailWriter::AddHeaderLine(line);
		m_qs.WriteBuffer(line.P, line.Size);
		m_qs.WriteBuffer("\n", 1);
		ExtraAddLine(line);
	}

	void AddBodyLine(RAString line) {
		BinaryWriter wr(m_qs);
		if (line.Size>=5 && !memcmp(line.P, "From ", 5))  // for UNIX mailbox
			wr << char('>');
		wr.Write(line.P, line.Size);
		wr << char('\n');
		ExtraAddLine(line);
	}

	void AfterHeader() {
		EmailWriter::AfterHeader();
		m_qs.WriteBuffer("\n", 1);
		ExtraAddLine(AString("", 0));
	}

	void Finish() {
		m_qs.WriteBuffer("\n", 1);
		if (CTcpMan::s_bEnableLog) {		
			ofstream ofs((const char*)Path::Combine(m_directory, "unix.mbx"), ios::app | ios::binary);
			Blob blob = m_qs.Blob;
			ofs.write((const char*)blob.constData(), (streamsize)blob.Size);			
		}
		EmailWriter::Finish();
	}
};

class OutPop3AnalyzerStream : public LineAnalyzerStream {
	void ProcessLine(const AString& line);
public:
	OutPop3AnalyzerStream() {
		m_rstage = 1;
	}
};

class InPop3AnalyzerStream : public LineAnalyzerStream {
	void ProcessLine(const AString& line);
public:
	InPop3AnalyzerStream() {
		m_wanted = 3;
	}

	void Process(const ConstBuf& data) override {
		switch (m_rstage) {
		case 0:
			if (memcmp(data.P, "+OK", 3)) {
				m_analyzer->Delete();
				return;
			} else {
				m_analyzer->Capture();
				m_rstage++;
			}
		}
		LineAnalyzerStream::Process(data);
	}
};

enum EPop3State {
	POP3STATE_INIT,
	POP3STATE_LOGIN,
	POP3STATE_RETR,
	POP3STATE_HEADER,
	POP3STATE_BODY
};

class Pop3Analyzer : public Analyzer {
	bool TryRecognize() override {
		if (!m_ci->GetWasSYN()) {
			Delete();
			return false;
		}
		return m_ci->DstEndPoint.Port%1000 == 110;
	}
public:
	String UserName,
		      Password;
	EPop3State Pop3State;
	ptr<EmailWriter> m_writer;

	OutPop3AnalyzerStream m_outStm;
	InPop3AnalyzerStream m_inStm;

	Pop3Analyzer()
		:	Pop3State(POP3STATE_INIT)
	{
		SetOutStm(&m_outStm);
		SetInStm(&m_inStm);
	}
};

class Pop3AnalyzerClass : public AnalyzerClass<Pop3Analyzer>
{
public:
	Pop3AnalyzerClass()
	{
		Priority = 20;
		Create("POP3");
	}
};

class OutSmtpAnalyzerStream : public LineAnalyzerStream {
	void ProcessLine(const AString& line);
public:
	OutSmtpAnalyzerStream() {
		m_rstage = 1;
	}

	void Process(const ConstBuf& data) override {
		switch (m_rstage) {
		case 0:
			if (memcmp(data.P, "HELO", 4) && memcmp(data.P, "EHLO", 4)) {
				m_analyzer->Delete();
				return;
			} else {
				m_analyzer->Capture();
				m_rstage++;
			}
		}
		LineAnalyzerStream::Process(data);
	}
};

class InSmtpAnalyzerStream : public LineAnalyzerStream {
public:
	InSmtpAnalyzerStream() {
		m_wanted = 4;
	}

	void Process(const ConstBuf& data) override {
		switch (m_rstage) {
		case 0:
			if (memcmp(data.P, "220 ", 4)) {
				m_analyzer->Delete();
				return;
			} else {
				m_analyzer->Capture();
				m_rstage++;
			}
		}
		LineAnalyzerStream::Process(data);
	}
};

enum ESmtpState {
	SMTPSTATE_INIT,
	SMTPSTATE_HELO,
	SMTPTATE_LOGIN,
	SMTPSTATE_HEADER,
	SMTPSTATE_BODY
};

class SmtpAnalyzer : public Analyzer {
	/*!!!
	bool m_capture;
	bool m_capture_message;
	String m_msg_to;
	String m_msg_from;
	String m_msg_subj;
	auto_ptr<ofstream> m_out;
	uint m_matches;
	uint m_current_line;
	uint m_first_match;
	enum match_states { sInit, sMailfrom, sRcptto, sStart, sEnd, sBadStream };
	match_states m_match_state;

	void Process(const ConstBuf& data, uint dir)
	{
		TRC(1, m_class->GetName() << "[" << m_id << "] is processing: " << m_info.dump() << " " << dir << " chunk: " << data.m_len);//!!!
		String line((const char *) data.m_p, data.m_len);
		m_current_line++;	
		if (! m_capture)	// Recognition
		{
			switch (m_match_state)
			{
				case sInit: {
					if (s_reMailFrom.IsMatch(line))
					{
						TRC(1, "* Mail from match at line " << m_current_line);
						m_matches++;
						m_first_match = m_current_line;
						m_match_state = sMailfrom;
						if ( dir == SERVER2CLIENT )	// Это сообщение от клиента к серверу, меняем.
							m_info.swap();
					}
					else if (m_current_line > 20 )	// Должно совпасть за 20 строк
					{
						TRC(1, "* No match with MAIL FROM: in 20 lines, aborting");
						m_match_state = sBadStream;
					}
					break;
				}
				case sMailfrom:	{
					if (Match m = s_reRcptTo.Match(line))
					{
						TRC(1, "* Rcpt to match at line " << m_current_line);
						m_matches++;
						m_match_state = sRcptto;
						m_user = UserManager::I().FindUserByID("smtp", m[1].Value);
						if (!m_user)
							UserManager::I().AddUser(m_user = new SmtpUser(m[1].Value, m_info.client_ip, m_info.server_ip));
					}
					else if (m_current_line - m_first_match > 1)
					{
						TRC(1, "* There is no rcpt to after mail from, aborting " << m_matches << " " << m_first_match << " " << m_current_line);
						m_match_state = sBadStream;
					}
					break;
				}
				case sRcptto: {
					if (s_reStart.IsMatch(line))
					{
						TRC(1, "* SMTP message start");
						m_match_state = sStart;
						m_capture = true;
						m_msg = m_user->NewMessage(m_dt);
					}
					break;
				}
				default: {
					TRC(1, "! Unknown state " << m_match_state << " at line " << m_current_line);
					break;
				}
			} // swtich
			if (m_match_state == sBadStream)
			{
				m_state[dir] = BadStream;
				m_processed[dir] = data.m_len;
				return;
			}
		} // if (!capture)
		else
		{
			if (s_reEnd.IsMatch(line))
			{
				TRC(1, "* end message");
				m_capture_message = false;
				m_capture = false;
				m_match_state = sInit;
				m_current_line = 0;
				m_user->Finish(m_msg);
				goto end;
			}
			if (!m_capture_message )
			{
				TRC(1, "* message header");
				Match m;
				if (s_reBlank.IsMatch(line))
				{
					TRC(1, "* message body");
					m_capture_message = true;
				}
			}
			m_msg->AddLine(line);
		} // else (capture)
end:	TRC(1, line);
		m_state[dir] = NeedMatch;
		m_processed[dir] = data.m_len;
	}
	*/

	bool TryRecognize() override {
		if (!m_ci->GetWasSYN()) {
			Delete();
			return false;
		}
		return m_ci->DstEndPoint.Port%100 == 25;
	}
public:	
	ESmtpState SmtpState;
	ptr<EmailWriter> m_writer;

	OutSmtpAnalyzerStream m_outStm;
	InSmtpAnalyzerStream m_inStm;

	SmtpAnalyzer()
		:	SmtpState(SMTPSTATE_INIT)
	{
		SetOutStm(&m_outStm);
		SetInStm(&m_inStm);
	}
};

class SmtpAnalyzerClass : public AnalyzerClass<SmtpAnalyzer> {
public:
	SmtpAnalyzerClass() {
		Priority = 20;
		Create("POP3");
	}
};

extern "C" {
	class CEmailMessageAnalyzerClass : public CMessageAnalyzerClass {
	public:
		CEmailMessageAnalyzerClass()
			:	CMessageAnalyzerClass("EMail")
		{}

		ptr<User> CreateUser() { return new EmailUser; }

		CMessageAnalyzer *CreateObject() {
			Users.Load();
			return new CMessageAnalyzer(new Pop3AnalyzerClass, new SmtpAnalyzerClass());
		}

		ptr<EmailWriter> CreateWriter() {
			ptr<EmailWriter> w;

			/*!!!
			String mf = ConnectionManager::I->MailboxFormat;
			if (mf == "EUDORA")
				w = new EudoraWriter;
			else
				w = new UnixWriter;
				*/
			w = new MemUnixWriter;
			w->Create();
#if UCFG_SNIF_PACKET_CAPTURE
			if (CTcpMan::s_bEnableLog)
				Directory::CreateDirectory(w->m_directory=Dir);
#endif
			return w;		
		}

	} g_emailMessageAnalyzerClass;
}

EmailWriter::EmailWriter()
{
  m_analyzerClass = &g_emailMessageAnalyzerClass;
}

EmailUser::EmailUser() {
	g_emailMessageAnalyzerClass.Users.AddInitial(this);
}

EmailUser *EmailUser::FindByServerLogin(const IPEndPoint& server, RCString login) {
	return static_cast<EmailUser*>(g_emailMessageAnalyzerClass.Users.GetByServerLogin(server, login).get());
}

EmailUser *EmailUser::GetByClientAddress(const IPAddress& ha) {
	return (EmailUser*)g_emailMessageAnalyzerClass.Users.GetByClientAddress(ha).get();
}

static regex s_reOk("^\\+OK"),
			 s_reUser("^USER\\s(.*)$"),
			 s_rePass("^PASS\\s(.*)$"),
			 s_reRetr("^RETR\\s(\\d+)$");

void OutPop3AnalyzerStream::ProcessLine(const AString& line) {
	Pop3Analyzer *pa = (Pop3Analyzer*)m_analyzer;
	cmatch m;
	if (regex_search((const char*)line.begin(), (const char*)line.end(), m, s_reUser))
		pa->UserName = m[1];
	else if (regex_search((const char*)line.begin(), (const char*)line.end(), m, s_rePass)) {
		pa->Password = m[1];
		pa->Pop3State = POP3STATE_LOGIN;
	}
	else if (regex_search((const char*)line.begin(), (const char*)line.end(), m, s_reRetr)) {
		pa->Pop3State = POP3STATE_RETR;
	}
}

void InPop3AnalyzerStream::ProcessLine(const AString& line) {
	Pop3Analyzer *pa = (Pop3Analyzer*)m_analyzer;
	switch (pa->Pop3State)
	{
	case POP3STATE_LOGIN:
		if (regex_search((const char*)line.begin(), (const char*)line.end(), s_reOk))
			(pa->m_user=EmailUser::FindByServerLogin(pa->m_ci->DstEndPoint, pa->UserName))->SetPassword(pa->Password);
		break;
	case POP3STATE_RETR:
		if (regex_search((const char*)line.begin(), (const char*)line.end(), s_reOk)) {
			pa->Pop3State = POP3STATE_HEADER;
			if (!pa->m_user)
				pa->m_user = EmailUser::GetByClientAddress(pa->m_ci->SrcEndPoint.Address);
			pa->m_writer = g_emailMessageAnalyzerClass.CreateWriter();
		}
		break;
	case POP3STATE_HEADER:
		if (!line.Size) {
			pa->m_writer->AfterHeader();
			pa->Pop3State = POP3STATE_BODY;
		} else
			pa->m_writer->AddHeaderLine(line);
		break;
	case POP3STATE_BODY:
		if (line.Size==1 && !memcmp(line.P, ".", 1)) {
			pa->m_writer->Direction = Direction::Incoming;
			pa->m_writer->Finish();
			pa->m_writer = nullptr;
			pa->Pop3State = POP3STATE_INIT;
		} else if (line.Size && !memcmp(line.P, ".", 1))
			pa->m_writer->AddBodyLine(AString(line.P+1, line.Size-1));
		else
			pa->m_writer->AddBodyLine(line);
		break;
	}
}

static regex s_reHelo("^(HELO|EHLO).*$", regex_constants::icase),
			s_reMailFrom("^MAIL\\sFROM:", regex_constants::icase),
			s_reRcptTo("^RCPT\\sTO:", regex_constants::icase),
			s_reData("^DATA$",	regex_constants::icase),
			s_reStart("^354\\s");

void OutSmtpAnalyzerStream::ProcessLine(const AString& line) {
	SmtpAnalyzer *sa = (SmtpAnalyzer*)m_analyzer;
	switch (sa->SmtpState)
	{
	case SMTPSTATE_INIT:
		if (regex_search((const char*)line.begin(), (const char*)line.end(), s_reHelo)) {
			sa->SmtpState = SMTPSTATE_HELO;
			break;
		}
		break;
	case SMTPSTATE_HELO:
		if (regex_search((const char*)line.begin(), (const char*)line.end(), s_reMailFrom)) {
//!!!			sa->m_user = EmailUser::FindByServerLogin(sa->m_ci->SrcEndPoint, "_user_");
//!!!			sa->m_user->Log();
			sa->m_writer = g_emailMessageAnalyzerClass.CreateWriter();
		}
		if (sa->m_writer)
			if (regex_search((const char*)line.begin(), (const char*)line.end(), s_reData))
				sa->SmtpState = SMTPSTATE_HEADER;
		break;
	case SMTPSTATE_HEADER:
		if (!line.Size) {
			sa->m_writer->AfterHeader();
			sa->SmtpState = SMTPSTATE_BODY;
		} else
			sa->m_writer->AddHeaderLine(line);
		break;
	case SMTPSTATE_BODY:
		if (line.Size==1 && !memcmp(line.P, ".", 1)) {
			sa->m_writer->Direction = Direction::Outgoing;
			sa->m_writer->Finish();
			sa->m_writer = nullptr;
			sa->SmtpState = SMTPSTATE_HELO;
		} else if (line.Size && !memcmp(line.P, ".", 1))
			sa->m_writer->AddBodyLine(AString(line.P+1, line.Size-1));
		else
			sa->m_writer->AddBodyLine(line);
	}
}

} // Snif::

