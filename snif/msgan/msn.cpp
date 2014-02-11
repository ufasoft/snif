/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "msgan.h"

namespace Snif {


/*!!!
class MsnChatSession
{
public:
	ptr<User> From,
		        To;
};

bool operator==(const MsnChatSession& x, const MsnChatSession& y)
{
	return x.From==y.From && x.To==y.To;
}

size_t hash_value(const MsnChatSession& x)
{
	return hash_value(x.From->m_id)+hash_value(x.To->m_id);
}
*/

class MsnAnalyzerStream : public LineAnalyzerStream {
	typedef LineAnalyzerStream base;
public:
	MsnAnalyzerStream()
		:	base(7)
	{}
private:
	UInt32 Cmd;
	String m_params;

	void Process(const ConstBuf& data) override;
	bool IsFromServer(regex& re, cmatch& m);
	void ProcessLine(const AString& line);
	void ProcessBinary(const ConstBuf& data);
};

class MsnAnalyzer : public Analyzer {
	String owner;

	typedef map<String, uint> PeersMap;
	PeersMap peers;

	bool TryRecognize() override;
public:
	CConnectionInfo m_extCi;
	StreamClient m_client0, m_client1;

	MsnAnalyzerStream m_outStm, m_inStm;

//!!!	CPointer<StreamClient> Clients[2];
	ptr<User> From, To;


	MsnAnalyzer() 
		:	m_client0(0, false)
		,	m_client1(0, true)
	{
		SetOutStm(&m_outStm);
		SetInStm(&m_inStm);
	}

	~MsnAnalyzer() {
		m_extCi.Analyzers.clear();			// to prevent recursion
	}
};


static wregex s_reSid(L"gateway.dll\\?.*SessionID=([^.]+)\\.");

class MsnAnalyzerClass : public AnalyzerClass<MsnAnalyzer>, HttpSubscription {
	typedef MsnAnalyzerClass class_type;

	typedef LruMap<String, ptr<MsnAnalyzer> > HttpAnalyzerMap;
	HttpAnalyzerMap HttpAnalyzers;

	void OnReceived(HttpDialog *dialog) {
		HttpDialog& d = *dialog;
		if (!!d.Response.Headers.Get("X-MSN-Messenger")) {
			String uri = d.Request.RequestUri;
			Smatch m;
			if (regex_search(uri, m, s_reSid)) {
				ptr<MsnAnalyzer> an;
				pair<HttpAnalyzerMap::iterator, bool> ii = HttpAnalyzers.insert(make_pair(String(m[1]), an));
				if (ii.second) {
					an = new MsnAnalyzer();
					an->m_extCi.SrcEndPoint = d.m_ci->SrcEndPoint;
					an->m_extCi.DstEndPoint = d.m_ci->DstEndPoint;
					an->m_ci = &an->m_extCi;
					an->m_ci->Analyzers.push_back(*an);
					ii.first->second.first = an;
					an->m_arStm[0]->SetStreamClient(&an->m_client0);
					an->m_arStm[1]->SetStreamClient(&an->m_client1);
				} else
					an = ii.first->second.first;
				an->m_client0.m_blob.Replace(an->m_client0.m_blob.Size, 0, d.Request.Data);
				an->m_client1.m_blob.Replace(an->m_client1.m_blob.Size, 0, d.Response.Data);


#ifdef _DEBUG//!!!D
			if (d.Request.Data.Size  || d.Response.Data.Size)
				dialog = dialog;
#endif
				an->m_arStm[0]->Process();
				an->m_arStm[1]->Process();
			}
		}
	}
public:
	static MsnAnalyzerClass *I;
	LruCache<CMessageItem> LastMessages;

	LruCache<IPEndPoint> SwitchBoards;

	MsnAnalyzerClass() {
		I = this;	
		Priority = 25;
		Create("MSN");
	}

	~MsnAnalyzerClass() {
		I = 0;
	}

};

MsnAnalyzerClass *MsnAnalyzerClass::I;

bool MsnAnalyzer::TryRecognize() {
	MsnAnalyzerClass *cl = MsnAnalyzerClass::I;
	if (cl->SwitchBoards.find(m_ci->DstEndPoint) != cl->SwitchBoards.end())	{
		Capture();
		return true;
	}
	if (m_ci->DstEndPoint.Port == 1863)
		return true;
//!!!	if (m_ci->SrcEndPoint.Port == 1863)
//!!!		return m_ci->TrySwapStreams();
	return false;
}

class MsnUser : public User {
public:
	MsnUser();
	static MsnUser *GetByIdNick(RCString email, RCString nick = "");
	static MsnUser *GetByClientAddress(const IPAddress& ha);
};

extern "C"  {
class CMsnMessageAnalyzerClass : public CMessageAnalyzerClass {
public:
	CMsnMessageAnalyzerClass()
		: CMessageAnalyzerClass("MSN")
	{}

	ptr<User> CreateUser() { return new MsnUser; }

	CMessageAnalyzer *CreateObject() {
		Users.Load();
		return new CMessageAnalyzer(new MsnAnalyzerClass);
	}
} g_msnMessageAnalyzerClass;
}

class MsnMessage : public Message {
public:
	MsnMessage() {
		m_analyzerClass = &g_msnMessageAnalyzerClass;
	}
};

MsnUser::MsnUser() {
	g_msnMessageAnalyzerClass.Users.AddInitial(this);
}

MsnUser *MsnUser::GetByIdNick(RCString email, RCString nick) {
	MsnUser *u = static_cast<MsnUser*>(g_msnMessageAnalyzerClass.Users.FindUserByID(email));
	if (!u) {
		u = new MsnUser;
		u->Uid = email;
		g_msnMessageAnalyzerClass.Users.Save();
	}
	if (u->get_Nick().IsEmpty() && !nick.IsEmpty() && nick.Length<20)
		u->Nick = nick;
	return u;
}

MsnUser *MsnUser::GetByClientAddress(const IPAddress& ha) {
	return (MsnUser*)g_msnMessageAnalyzerClass.Users.GetByClientAddress(ha).get();
}

static bool IsUpperAlpha(char ch) {
	return ch>='A' && ch<='Z';
}

static regex //!!!R s_reMsn("^([A-Z][A-Z][A-Z])( \\w+)?( (.*))?"),
				s_reMsn("([A-Z0-9][A-Z0-9][A-Z0-9])(?: \\w+)?((?:.*) (\\d+)|(?:.*))"),		// cmd - 1   params - 2  length - 3
				s_reXfr("^[A-Z]+( (\\S+) CKI (.*))?"),
				s_reUsr("^(OK )?(\\S+) (.*)$"),
				s_reRng("^(\\S+) CKI \\S+ (\\S+) (.*)$"),
				s_reAns("^(OK)|(\\S+) (\\S+) (.*)$"),
				s_reJoi("^(\\S+) (\\S+)( (\\S+))?.*$"),
				s_reIro("^\\d+ \\d+ (\\S+) (\\S+)( (\\S+))?.*$");

static wregex s_reContentType(L"^text/plain;"),
				s_reCharSet(L"charset=([^;]+)");

void MsnAnalyzerStream::Process(const ConstBuf& data) {
	switch (m_rstage) {
	case 0:
		if (data.P[3]!=' ' || !IsUpperAlpha(data.P[0]) || !IsUpperAlpha(data.P[1]) || !IsUpperAlpha(data.P[2])) {
			m_analyzer->Delete();
			return;
		}
		m_rstage = 1;
	}
	LineAnalyzerStream::Process(data);
}

bool MsnAnalyzerStream::IsFromServer(regex& re, cmatch& m) {
	if (regex_search(m_params.c_str(), m, re))
		return String(m[1]) != "";
	else
		Throw(E_FAIL);
}

void MsnAnalyzerStream::ProcessLine(const AString& line) {
	MsnAnalyzerClass& cl = *MsnAnalyzerClass::I;
	MsnAnalyzer& ma = *(MsnAnalyzer*)m_analyzer;
	cmatch m;
	if (regex_match((const char*)line.begin(), (const char*)line.end(),  m, s_reMsn)) {
		String cmd = m[1];
		m_params = String(m[2]).Trim();

		Cmd = Fast_ntohl(*(UInt32*)(const char*)cmd) >> 8;
		switch (Cmd) {
		case 'ANS':
			if (!IsFromServer(s_reAns, m))
				ma.From = MsnUser::GetByIdNick(m[2]);
			break;
		case 'IRO':
			IsFromServer(s_reIro, m);
			ma.To = MsnUser::GetByIdNick(m[1], m[2]);
			break;
		case 'JOI':
			IsFromServer(s_reJoi, m);
			ma.To = MsnUser::GetByIdNick(m[1], m[2]);
			break;
		case 'RNG':
			IsFromServer(s_reRng, m);
			cl.SwitchBoards.insert(IPEndPoint(m[1]));
			break;
		case 'USR':
			if (IsFromServer(s_reUsr, m))
				ma.From = MsnUser::GetByIdNick(m[2]);
			break;
		case 'XFR':
			if (IsFromServer(s_reXfr, m))
				cl.SwitchBoards.insert(IPEndPoint(m[2]));
			break;
		case 'ADL':
		case 'QRY':
		case 'PUT':
		case 'SDG':
		case 'DEL':
		case 'FQY':
		case 'GCF':					// with Payload
		case 'GET':
		case 'IPG':
		case 'MSG':
		case 'NFY':
		case 'NOT':
		case 'RML':
		case 'UBM':
		case 'UBN':
		case 'UBX':
		case 'UUN':
		case '203':
		case '204':
		case '205':
		case '210':
		case '234':
		case '241':
		case '508':
		case '509':
		case '511':
		case '933':
			if (m_wanted = atoi(String(m[3]))) {
				m_state = ASTATE_NEED_MORE;
				BinaryMode = true;
			}
			break;
		}
	} else {
		m_analyzer->Delete();
	}
}

void MsnAnalyzerStream::ProcessBinary(const ConstBuf& data) {
	MsnAnalyzer& ma = *(MsnAnalyzer*)m_analyzer;
	CMemReadStream stm(data);
	switch (Cmd) {
		case 'MSG':
			{
				CHttpHeader hdr;
				hdr.ParseHeader(ReadHttpHeader(stm), true);
				String tuser = hdr.Headers.Get("TypingUser"),
								ct = hdr.Headers.Get("Content-Type");
				if (!!tuser) {
					if (IsOut && !ma.From)
						ma.From = MsnUser::GetByIdNick(tuser);
					else if (!IsOut && !ma.To)
						ma.To = MsnUser::GetByIdNick(tuser);
				}
				if (!!ct) {
					if (regex_search(ct, s_reContentType)) {			//!!! UTF-8 only
						ptr<User> from = ma.From ? ma.From : MsnUser::GetByClientAddress(ma.m_ci->SrcEndPoint.Address),
							to = ma.To ? ma.To : MsnUser::GetByIdNick("_unknown_");
						from->ClientAddress = ma.m_ci->SrcEndPoint.Address;
						to->ClientAddress = ma.m_ci->DstEndPoint.Address;
						if (!IsOut)
							swap(from, to);
						CMessageItem mi(from, to, UTF8Encoding().GetChars(ConstBuf(data.P+stm.Position, data.Size-(size_t)stm.get_Position())));
						if (IsOut)
							MsnAnalyzerClass::I->LastMessages.insert(mi);
						else if (MsnAnalyzerClass::I->LastMessages.find(mi) != MsnAnalyzerClass::I->LastMessages.end())
							return;
						ptr<MsnMessage> msg = new MsnMessage;
						msg->From = from;
						msg->To = to;
						msg->Text = mi.second;
						msg->Finish();
					}
				}
			}
			break;
		case 'SDG':
			{
				CHttpHeader hdr1;
				hdr1.ParseHeader(ReadHttpHeader(stm), true);
				String serviceChannel = hdr1.Headers.Get("Service-Channel");
				String to = hdr1.Headers.Get("To"),
						from = hdr1.Headers.Get("From");
				if ((!serviceChannel || serviceChannel=="IM/Online" || serviceChannel=="IM/Offline") && !!to && !!from) {					
					vector<String> vTo = to.Split(":");
					vector<String> vFrom = from.Split(";");
					if (vTo.size() > 1 && vFrom.size() > 0) {
						to = vTo[1];
						from = vFrom[0];
						vFrom = from.Split(":");
						if (vFrom.size() > 1) {
							from = vFrom[1];

							CHttpHeader hdr2;
							hdr2.ParseHeader(ReadHttpHeader(stm), true);

							CHttpHeader hdr3;
							hdr3.ParseHeader(ReadHttpHeader(stm), true);
							String messageType = hdr3.Headers.Get("Message-Type");
							if (messageType == "Text") {
								String contLen = hdr3.Headers.Get("Content-Length");
								size_t len = !!contLen ? atoi(contLen) : size_t(stm.Length-stm.Position);
								ConstBuf mb(data.P+stm.Position, len);
								String ct = hdr3.Headers.Get("Content-Type");
								Encoding *enc = &Encoding::UTF8;
								if (!!ct) {
									Smatch m;
									if (regex_search(ct, m, s_reCharSet))
										enc = Encoding::GetEncoding(m[1]);
								}
								String text = enc->GetChars(mb);
								ptr<MsnMessage> msg = new MsnMessage;
								msg->From = MsnUser::GetByIdNick(from);
								msg->To = MsnUser::GetByIdNick(to);
								msg->Text = text;
								msg->Finish();
							}
						}
					}
				}
			}
			break;
	}
}


} // Snif::

