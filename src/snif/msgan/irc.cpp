/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

// Based on RFC 2819


#include "msgan.h"

namespace Snif {


class IrcMessage : public Message {
	void SaveFrom() {
		if (To->get_Nick().Left(1) != "#")
			Message::SaveFrom();
	}
public:
	IrcMessage();
};

/*!!!
class IrcChannelMessage : public IrcMessage
{
	void Finish()
	{
		String from = !From->m_nick.IsEmpty() ? From->m_nick : From->ClientAddress.ToString();
		ostringstream os;
		os << DateTime << " <" << from  << "> " << Text;
		ofstream(Path::Combine(m_analyzerClass->Dir, Channel), ios::app) << os.str() << endl;; //!!!? may be network (EFNet also)
		ostringstream os2;
		os2 << DateTime << " <" << from << ">->" << Channel << "\t" << Text;
		PLogMessage(os2.str());
	}
public:
	String Channel;
};*/

class IrcUser : public User {
public:
	IrcUser();
	static IrcUser *GetByNick(RCString nick);
	static IrcUser *GetByClientAddress(const IPAddress& ha);
};


class IrcDccAnalyzerStream : public LineAnalyzerStream {
	void ProcessLine(const AString& line) {

		//!!!TODO
		TRC(2, "IRC DCC " << String((const char*)line.P, line.Size) );
	}
public:
	IrcDccAnalyzerStream() {
		m_rstage = 1; // need for LineAnalyzerStream
	}
};

class IrcDccAnalyzer : public Analyzer {
	bool TryRecognize() override;
public:
	IrcDccAnalyzerStream m_outStm, m_inStm;

	IrcDccAnalyzer() {
		SetOutStm(&m_outStm);
		SetInStm(&m_inStm);
	}
};

class IrcDccAnalyzerClass : public AnalyzerClass<IrcDccAnalyzer> {
public:
	IrcDccAnalyzerClass() {
		Priority = 14;
		Create("IRCDcc");
	}
};

class IrcAnalyzerStream : public LineAnalyzerStream {
	void ProcessLine(const AString& line);
public:
	IrcAnalyzerStream() {
		m_rstage = 1; // need for LineAnalyzerStream
	}
};

class IrcAnalyzer : public Analyzer {
	int m_nFailure,
		  m_nSuccess;

	bool TryRecognize() override {
		UInt16 dstPort = m_ci->DstEndPoint.Port,
			   srcPort = m_ci->SrcEndPoint.Port;
		if (dstPort >=6667 && dstPort <= 6672)
			return true;
		if (srcPort >=6667 && srcPort <= 6672)
			return m_ci->TrySwapStreams();
		return false;
	}
public:
	static int s_AnalyzerID;
	int ID;
//!!!	String m_nick;

	IrcAnalyzerStream m_outStm, m_inStm;
	
	IrcAnalyzer()
		:	ID(++s_AnalyzerID)
		,	m_nFailure(0)
		,	m_nSuccess(0)
	{
		SetOutStm(&m_outStm);
		SetInStm(&m_inStm);
	}	

	void IncrementFailure() {
		if (m_nFailure++ >= 3)
			Delete();
	}

	void IncrementSuccess() {
		if (m_nSuccess++ >= 10)
			Capture();
	}
};

int IrcAnalyzer::s_AnalyzerID;

class IrcAnalyzerClass : public AnalyzerClass<IrcAnalyzer> {
public:	
	static IrcAnalyzerClass *I;

	LruCache<CMessageItem> LastMessages;
	LruCache<IPEndPoint> DccEndpoints;

	IrcAnalyzerClass() {
		I = this;
		Priority = 15;
		Create("IRC");
	}

	~IrcAnalyzerClass() {
		I = 0;
	}
};

IrcAnalyzerClass *IrcAnalyzerClass::I;

extern "C"  {
class CIrcMessageAnalyzerClass : public CMessageAnalyzerClass {
public:
	CIrcMessageAnalyzerClass()
		:	CMessageAnalyzerClass("IRC")
	{}

	CMessageAnalyzer *CreateObject() { return new CMessageAnalyzer(new IrcAnalyzerClass, new IrcDccAnalyzerClass); }

	ptr<User> CreateUser() { return new IrcUser; }

} g_ircMessageAnalyzerClass;
}

IrcMessage::IrcMessage() {
	m_analyzerClass = &g_ircMessageAnalyzerClass;
}

IrcUser::IrcUser() {
	g_ircMessageAnalyzerClass.Users.AddInitial(this);
}

IrcUser *IrcUser::GetByNick(RCString nick) {
	return static_cast<IrcUser*>(g_ircMessageAnalyzerClass.Users.GetByNick(nick).get());
}

IrcUser *IrcUser::GetByClientAddress(const IPAddress& ha) {
	return static_cast<IrcUser*>(g_ircMessageAnalyzerClass.Users.GetByClientAddress(ha).get());
}

bool IrcDccAnalyzer::TryRecognize() {
	if (!m_ci->GetWasSYN())
		Delete();
	else {
		if (IrcAnalyzerClass::I->DccEndpoints.erase(m_ci->DstEndPoint)) {
			Capture();
			return true;
		}
	}
	return false;
}

static wregex s_reMessage(String("(:([^ !]+)(?:(?:!([^@]+))?@(\\S+))? )?"			// prefix - 1  nickname - 2   user - 3  host - 4  command - 5   params - 6   trailing - 7
													"([A-Za-z]+|(?:\\d\\d\\d))"
													"(?:((?: [^: ][^ ]*){0,14})(?: :?(.*))?)?")),

					//	 s_rePrefix("^:(.+?)\\s(.+)$"),
             s_reCmd(String("^(\\w+)\\s+(.*?)\\s?:(.*)$")),
						 s_reCmd2(String("^([\\w|\\d]+)\\s(.*)$")),
						 s_reCmd3(String("^(\\w+)\\s+(.*?)\\s:?(.*)$")),		// PRIVMSG dest oneword
						 s_reExclamation(String("^(.*)!(.*)$")),
						 s_reChat(String("^\001DCC\\sCHAT\\schat\\s(\\d+)\\s(\\d+)\001$")),
						 s_rePing(String("^PING")),
						 s_rePrivmsg(String("^PRIVMSG")),
						 s_reNick(String("^NICK\\s")),
						 s_reDigits(String("^\\d+$"));

void IrcAnalyzerStream::ProcessLine(const AString& aline) {
	IrcAnalyzer *ia = (IrcAnalyzer*)m_analyzer;

	if (aline.Size > 0) {
		byte ch = aline.P[0];
		if (ch >= 128)
			return ia->IncrementFailure();
	}

	Encoding::CIgnoreIncorrectChars ignoreIncorrectChars;

	Encoding *enc = g_encMessage;
#ifdef WIN32
	static CodePageEncoding s_ansiEncoding(CP_ACP);
	if (!g_bEncChanged)
		enc = &s_ansiEncoding;
#endif
	String line = enc->GetChars(aline);
	
	Smatch m;
	if (!regex_match(line, m, s_reMessage))
		return ia->IncrementFailure();

	/*!!!
	if (s_rePing.Match(line) || s_rePrivmsg.Match(line) || s_reNick.Match(line))
	{
		m_analyzer->Capture();
		if (!IsOut)
			ia->m_ci->TrySwapStreams();
	}*/

	ia->IncrementSuccess();
	String nickname = m[2],
		      cmd = m[5],
		      param = String(m[6]).Trim(),
					args = m[7];
	if (m[1] != "") {
		if (ia->m_bCaptured && IsOut)
			ia->m_ci->TrySwapStreams();
		if (cmd == "JOIN") {
			TRC(1, "XXX: Join channel");
		}
		else if (cmd == "NICK") {
			TRC(1, "XXX: Nickname change");
		}
		else if (cmd == "NOTICE" && param != "AUTH")
			ia->m_user = IrcUser::GetByNick(param); //!!!
	} else { // Outgoing
		if (cmd == "NICK")
			ia->m_user = IrcUser::GetByNick(args);
	}
	if (cmd == "PRIVMSG") {
		Smatch what;
		if (regex_search(args, what, s_reChat)) {
			TRC(1, "* DCC connection attempt");
			IrcAnalyzerClass::I->DccEndpoints.insert(IPEndPoint(htonl((DWORD)atoi(String(what[1]))),
														(WORD)atoi(String(what[2]))));
		} else {
			if (param.Left(1)!="#" && !ia->m_user)
				ia->m_user = IrcUser::GetByNick(param);
			ptr<User> to = IrcUser::GetByNick(param),
				        from;
			if (!nickname.IsEmpty())
				from = IrcUser::GetByNick(nickname);
			else if (ia->m_user)
				from = ia->m_user;
			else
				from = IrcUser::GetByClientAddress(ia->m_ci->SrcEndPoint.Address);	
			pair<LruCache<CMessageItem>::iterator, bool> ii = IrcAnalyzerClass::I->LastMessages.insert(CMessageItem(from, to, args));
			if (ii.second || ii.first->first.AnalyzerID==ia->ID)
			{
				ii.first->first.AnalyzerID = ia->ID;
				ptr<IrcMessage> msg = new IrcMessage;
				msg->To = to;
				msg->From = from;
				msg->Text = args;
				msg->Finish();
			}
		}
	}	
}


} // Snif::
