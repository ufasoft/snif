/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

// Based on RFC 959

#include "msgan.h"

namespace Snif {

class FtpUser : public User {
public:
	FtpUser();
	static FtpUser *FindByServerLogin(const IPEndPoint& server, RCString login);
};

class OutFtpAnalyzerStream : public LineAnalyzerStream {
	void ProcessLine(const AString& line);
public:	
	OutFtpAnalyzerStream() {
		m_rstage = 1;
	}
};

class InFtpAnalyzerStream : public LineAnalyzerStream {
	void ProcessLine(const AString& line);

	void Process(const ConstBuf& data) override {
		switch (m_rstage) {
		case 0:
			if (memcmp(data.P, "220", 3)) {
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

class FtpFileMessage : public WebMessage, public FileTransfer {
	typedef WebMessage base;
public:
	String Filename;
	FileStream m_stm;
};

class FtpAnalyzer : public Analyzer {
	bool TryRecognize() override {
		if (!m_ci->GetWasSYN()) {
			Delete();
			return false;
		}
		return m_ci->DstEndPoint.Port==21;
	}
public:
	String ServerName;
	String UserName,
		      Password;

	OutFtpAnalyzerStream m_outStm;
	InFtpAnalyzerStream m_inStm;

	IPEndPoint m_epData;

	FtpAnalyzer() {
		SetOutStm(&m_outStm);
		SetInStm(&m_inStm);
	}

	void PrepareEndpoint(RCString sEp);
	void TrackMessage(FtpFileMessage *fm);
};

class FtpAnalyzerClass : public AnalyzerClass<FtpAnalyzer> {
public:	
	static FtpAnalyzerClass *I;
	typedef LruMap<IPEndPoint, ptr<FtpFileMessage> > CDataEndpoints;
	CDataEndpoints DataEndpoints;

	FtpAnalyzerClass() {
		I = this;
		Priority = 21;
		Create("FTP");
	}

	~FtpAnalyzerClass() {
		I = 0;
	}
};

class FtpDataAnalyzerStream : public AnalyzerStream {
public:
	FtpDataAnalyzerStream() {
		m_state = ASTATE_OK;
	}

	void Process(const ConstBuf& data) override;
};

class FtpDataAnalyzer : public Analyzer {
	bool TryRecognize() override;
public:
	ptr<FtpFileMessage> FileMessage;
	FtpDataAnalyzerStream m_outStm, m_inStm;

	FtpDataAnalyzer() {
		SetOutStm(&m_outStm);
		SetInStm(&m_inStm);
	}
};

void FtpDataAnalyzerStream::Process(const ConstBuf& data) {
	FtpDataAnalyzer *fda = (FtpDataAnalyzer*)m_analyzer;
	if (fda->FileMessage && fda->FileMessage->m_stm.m_fstm)
		fda->FileMessage->m_stm.WriteBuffer(data.P, data.Size);
	m_processed = data.Size;
}

class FtpDataAnalyzerClass : public AnalyzerClass<FtpDataAnalyzer> {
public:
	FtpDataAnalyzerClass() {
		Priority = 15;
		Create("FTPData");
	}
};

FtpAnalyzerClass *FtpAnalyzerClass::I;

class CFtpMessageAnalyzerClass : public CMessageAnalyzerClass {
public:
	CFtpMessageAnalyzerClass()
		:	CMessageAnalyzerClass("FTP")
	{}

	ptr<User> CreateUser() { return new FtpUser; }


	CMessageAnalyzer *CreateObject() {
		Users.Load();
		return new CMessageAnalyzer(new FtpAnalyzerClass, new FtpDataAnalyzerClass);
	}
} g_ftpMessageAnalyzerClass;

static wregex s_reEndpoint(String("(\\d+),(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)"));

void FtpAnalyzer::PrepareEndpoint(RCString sEp) {
	Smatch m;
	if (regex_search(sEp, m, s_reEndpoint)) {
		m_epData = IPEndPoint(htonl((atoi(String(m[1]))<<24) | (atoi(String(m[2]))<<16) | (atoi(String(m[3]))<<8) | atoi(String(m[4]))),
																	WORD((atoi(String(m[5]))<<8)|atoi(String(m[6]))));
	} else
		Throw(E_FAIL);
}

void FtpAnalyzer::TrackMessage(FtpFileMessage *fm) {
	FtpAnalyzerClass::I->DataEndpoints.insert(FtpAnalyzerClass::CDataEndpoints::value_type(m_epData, fm));
	
	TRC(1, m_epData);
}

bool FtpDataAnalyzer::TryRecognize() {
	if (m_ci->GetWasSYN()) {
		TRC(2, m_ci->DstEndPoint);

		FtpAnalyzerClass::CDataEndpoints::iterator it = FtpAnalyzerClass::I->DataEndpoints.find(m_ci->DstEndPoint);
		if (it != FtpAnalyzerClass::I->DataEndpoints.end()) {
			FileMessage = it->second.first;
			FtpAnalyzerClass::I->DataEndpoints.erase(it);
			Capture();

#if UCFG_SNIF_PACKET_CAPTURE
			if (CTcpMan::s_bEnableLog && FileMessage && g_opt_SaveFiles) {
				String dir = Path::Combine(g_ftpMessageAnalyzerClass.Dir, "files");
				String fullpath = AddDirSeparator(dir)+ FileMessage->Filename;
				Directory::CreateDirectory(Path::GetDirectoryName(fullpath));
				FileMessage->m_stm.Open(fullpath, FileMode::Create, FileAccess::Write);
			}
#endif
			return true;
		}
	}
	Delete();
	return false;
}

static regex s_reFtpCommand("^(\\w+)(\\s+(\\S+))?"),
		s_reFtpResponse("^(\\d+)\\s*");


void OutFtpAnalyzerStream::ProcessLine(const AString& line) {
	FtpAnalyzer *fa = (FtpAnalyzer*)m_analyzer;
	cmatch m;
	if (regex_search((const char*)line.begin(), (const char*)line.end(), m, s_reFtpCommand)) {
		String cmd = m[1];
		String arg = m[3];
		if (cmd == "USER")
			fa->UserName = arg;
		else if (cmd == "PASS")
			fa->Password = arg;
		else if (cmd == "RETR" || cmd == "STOR") {
			ptr<FtpFileMessage> fm = new FtpFileMessage;
			fm->m_analyzerClass = &g_ftpMessageAnalyzerClass;
			fm->ClientAddress = fa->m_ci->SrcEndPoint.Address;
			fm->From = WebUser::GetByClientAddress(fm->ClientAddress);
			String servername = !!fa->ServerName ? fa->ServerName : fa->m_ci->DstEndPoint.Address.ToString();
			fm->Text = "ftp://"+servername+arg;
			fm->Filename = arg;
			fm->Finish();
			fa->TrackMessage(fm.get());
		} else if (cmd == "PORT") {
			fa->PrepareEndpoint(arg);
		}
	} else
		fa->Delete();
}

FtpUser::FtpUser() {
	g_ftpMessageAnalyzerClass.Users.AddInitial(this);
}

FtpUser *FtpUser::FindByServerLogin(const IPEndPoint& server, RCString login) {
	return static_cast<FtpUser*>(g_ftpMessageAnalyzerClass.Users.GetByServerLogin(server, login).get());
}

void InFtpAnalyzerStream::ProcessLine(const AString& line) {
	FtpAnalyzer *fa = (FtpAnalyzer*)m_analyzer;
	cmatch m;
	if (regex_search((const char*)line.begin(), (const char*)line.end(), m, s_reFtpResponse)) {
		int code = atoi(String(m[1]));
		switch (code)
		{
		case 220:
			{
				ASCIIEncoding enc;
				String s = enc.GetChars(line);
				vector<String> vec = s.Split();
				if (vec.size() >= 2 && vec[1].Find(".") != -1)
					fa->ServerName = vec[1];
			}
			break;
		case 227:
			fa->PrepareEndpoint(ASCIIEncoding().GetChars(line));
			break;
		case 230:
			if (fa->UserName!="anonymous" && !fa->m_user)
				(fa->m_user=FtpUser::FindByServerLogin(fa->m_ci->DstEndPoint, fa->UserName))->SetPassword(fa->Password);
			break;
		}
	}
}

} // Snif::


