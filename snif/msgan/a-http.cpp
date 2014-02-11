/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

// Based on RFC 2068

#include "msgan.h"

namespace Snif {


HttpAnalyzerClass *HttpAnalyzerClass::I;


HttpAnalyzer::HttpAnalyzer() {
	m_outStm.HttpHeader = &Request;
	SetOutStm(&m_outStm);
	m_inStm.HttpHeader = &Response;
	SetInStm(&m_inStm);
}

void HttpAnalyzer::Finish() {
	if (m_arStm[1]->m_rstage==4)
		ProcessSubscribers();
}

bool HttpAnalyzer::TryRecognize() {
	
	return m_ci->GetWasSYN();  //!!! to preprocess CONNECT
	/*!!!
	if (!m_ci->TcpConnection->GetWasSYN())
	{
		Delete();
		return false;
	}
	*/

	/*!!!
	switch (m_ci->DstEndPoint.Port)
	{
	case 80:
	case 443:
	case 3128:
	case 8080:
		return true;
	}
	return false;
	*/
}

void HttpAnalyzer::AfterResponse() {
//	TRC(0, "");

	if (Request.Method == "CONNECT") {
		if (Response.Code != 200)
			Capture();
		else {
//!!!			for (Cpriority2anclassMultimap::iterator i=ConnectionManager::I->m_priority2anclass.begin(); i!=ConnectionManager::I->m_priority2anclass.end(); ++i)
//!!!				m_ci->Analyzers.push_back(i->second->CreateObject());
			for (CAnalyzerList::iterator i=m_ci->PotentialAnalyzers.begin(), e=m_ci->PotentialAnalyzers.end(); i!=e; ++i) {
				((Analyzer&)(*i)).m_arStm[0]->m_offset = m_arStm[0]->m_wanted;
				((Analyzer&)(*i)).m_arStm[1]->m_offset = m_arStm[1]->m_wanted;
			}
			m_ci->DstEndPoint = IPEndPoint(Request.RequestUri);
		}
		Delete();
	} else {
		ProcessSubscribers();
		m_arStm[1]->m_rstage = m_arStm[0]->m_rstage = 1;
		m_arStm[0]->m_state = ASTATE_NEED_MORE;
		m_arStm[1]->m_state = ASTATE_NO_NEED;
		m_arStm[1]->m_wanted = m_arStm[0]->m_wanted = 4;
	}
}

void HttpAnalyzer::ProcessSubscribers() {
//!!!	TRC(0, HttpAnalyzerClass::I->m_subscriber.m_set.size() << " subscribers");
	

	HttpDialog dialog;
	dialog.Request = Request;
	dialog.Response = Response;
	dialog.m_ci = m_ci;
	HttpAnalyzerClass *hac = HttpAnalyzerClass::I;


	for (CSubscriber<HttpSubscription>::CSet::iterator i=hac->m_subscriber.m_set.begin(), e=hac->m_subscriber.m_set.end(); i!=e; ++i) {
		try {
			(*i)->OnReceived(&dialog);
		} catch (RCExc e) {
			cerr << e << endl;
		}
	}
}

void HttpAnalyzerStream::AfterMessage() {
	HttpAnalyzer& ha = *(HttpAnalyzer*)m_analyzer;

	if (HttpHeader->Headers.Get("Content-Encoding") == "gzip") {
		CMemReadStream ms(HttpHeader->Data);
		GZipStream gstm(ms, CompressionMode::Decompress);
		MemoryStream qs;
		for (int v; (v=gstm.ReadByte())!=-1;)
			qs.WriteBuffer(&v, 1);
		HttpHeader->Data = qs.Blob;
	}

	if (!IsOut)
		ha.AfterResponse();
}

void HttpAnalyzerStream::Process(const ConstBuf& data) {
//	TRC(0, data.m_len << "\tStage: " << m_rstage << "\tState: " << m_state);

	HttpAnalyzer& ha = *(HttpAnalyzer*)m_analyzer;
	switch (m_rstage) {
	case 1:
		{
			m_state = ASTATE_OK;
			const byte *p = data.Find(ConstBuf((const byte*)"\n\n", 2)),
				         *q = data.Find(ConstBuf((const byte*)"\r\n\r\n", 4));
			if (p || q) {
	#ifdef _DEBUG //!!!D
				String source = m_analyzer->m_ci->SrcEndPoint.ToString();
				String dest = m_analyzer->m_ci->DstEndPoint.ToString();
	#endif
				size_t lenP = p ? p-data.P+2 : INT_MAX,
						   lenQ = q ? q-data.P+4 : INT_MAX;
						
				CMemReadStream stm(ConstBuf(data.P, m_processed=min(lenP, lenQ)));
				if (m_processed>2 && data.P[0]==0xD && data.P[1]==0xA)
					stm.ReadBuffer(0, 2); //!!! error in MSN Messegner: it inserts 0d0a after request
				vector<String> ar = ReadHttpHeader(stm);
				if (!stm.Eof())
					Throw(E_FAIL);						
				HttpHeader->Parse(ar);
				if (IsOut) {
					ha.m_arStm[1]->m_wanted = 4;
					ha.m_arStm[1]->m_rstage = 0;
					ha.m_arStm[1]->m_state = ASTATE_NEED_MORE;
				}
				if (ha.Request.Method == "CONNECT") {
					m_wanted = m_processed;
					m_state = ASTATE_NO_NEED;
					if (!IsOut)
						ha.AfterResponse();
				} else {
					m_analyzer->Capture();
					if (!IsOut) {
						bool bSkipContent = ha.Request.Method == "HEAD";
						if (!bSkipContent) {
							switch (ha.Response.Code) {
							case 204:
							case 304:
								bSkipContent = true;
								break;
							default:
								bSkipContent = ha.Response.Code>=100 && ha.Response.Code<=199;
							}
						}
						if (bSkipContent) {
							ha.AfterResponse();
							break;
						}
					}
					String slen = HttpHeader->Headers.Get("Content-Length"); //!!!TODO: chunked
					if (!slen) {
						String transferEncoding = HttpHeader->Headers.Get("Transfer-Encoding");
						if (!!transferEncoding && transferEncoding.ToLower() == "chunked") {
							m_wanted = 5;
							m_state = ASTATE_NEED_MORE;
							m_rstage = 5;

#ifdef X_DEBUG
						{
							static int s_i;
							++s_i;
							FileStream fs("c:\\tmp\\chunked.gz", FileMode::Create, FileAccess::Write);
							fs.WriteBuffer(data.m_p, data.m_len);
						}
#endif

						} else {
							if (IsOut)
								m_state = ASTATE_NO_NEED;
							else
								m_rstage = 4;
						}
					} else {
						m_rstage = 2;
						u_int64_t len = Convert::ToUInt64(slen);
						if (!len) {
							m_state = ASTATE_NO_NEED;
							if (!IsOut)
								ha.AfterResponse();
						} else if (len > HTTP_MAX_CONTENT) {
							HttpHeader->m_bDataSkipped = true;
							m_nToSkip = len;
							m_state = ASTATE_OK;
						} else {
							m_wanted = (size_t)len;
							m_state = ASTATE_NEED_MORE;
						}
					}
				}
			}
		}
		break;
	case 2:
		switch (m_state) {
		case ASTATE_NEED_MORE:
			HttpHeader->Data = ConstBuf(data.P, m_processed=m_wanted);
			m_state = ASTATE_NO_NEED;
			AfterMessage();
			break;
		case ASTATE_OK:
			m_processed = (size_t)std::min(m_nToSkip, (UInt64)data.Size);
			if (!(m_nToSkip-=m_processed)) {
				if (!IsOut)
					ha.AfterResponse();
				else
					m_state = ASTATE_NO_NEED;
			}
			break;
		}
		break;
	case 4:
		m_processed = data.Size;
		if (!HttpHeader->m_bDataSkipped) {
			HttpHeader->Data.Replace(HttpHeader->Data.Size, 0, data);
			if (HttpHeader->Data.Size > HTTP_MAX_CONTENT) {
				HttpHeader->m_bDataSkipped = true;
				HttpHeader->Data = Blob();
			}
		}
		break;
	case 5:		// chunked len
		{
			if (const byte *p = data.Find(ConstBuf((const byte*)"\r\n", 2))) {
				m_processed = p-data.P+2;
				String slen((const char*)data.P, m_processed-2);
				slen = slen.Trim();
				UInt64 len = Convert::ToUInt64(slen, 16);
				if (0 == len) {
					m_processed += 2;
					m_state = ASTATE_NO_NEED;
					AfterMessage();
				} else if (len > HTTP_MAX_CONTENT) {
					m_analyzer->Delete();
				} else {
					m_wanted = size_t(len+2);
					m_rstage = 6;
				}
			} else
				++m_wanted;
		}
		break;
	case 6:		// chunked data
		HttpHeader->Data.Replace(HttpHeader->Data.Size, 0, ConstBuf(data.P, m_wanted-2));
		m_processed = m_wanted;
		m_rstage = 5;
		m_wanted = 5;
		break;
	}
}

void OutHttpAnalyzerStream::Process(const ConstBuf& data) {
//	TRC(0, data.m_len << "\tStage: " << m_rstage);

	if (m_rstage == 0) {
		UInt32 method = Fast_ntohl(*(UInt32*)data.P) >> 8;
		switch (method) {
		case 'CON': // CONNECT
		case 'DEL': // DELETE
		case 'GET': // GET
		case 'HEA': // HEAD
		case 'OPT': // OPTIONS
		case 'POS': // POST
		case 'PUT': // PUT
		case 'TRA': // TRACE
//			cout.write((char*)data.m_p, data.m_len); //!!!D

			m_rstage++;
			break;
		default:
			m_analyzer->Delete();
			return;
		}
	}
	HttpAnalyzerStream::Process(data);
}

void InHttpAnalyzerStream::Process(const ConstBuf& data) {
//	TRC(0, data.m_len << "\tStage: " << m_rstage);

	switch (m_rstage)
	{
	case -1:
		if (m_analyzer->m_ci->GetWasSYN())
			m_analyzer->Delete();
		else
			Skip(data.Size);
		return;
	case 0:
		if (Fast_ntohl(*(UInt32*)data.P) == 'HTTP')
			m_rstage++;
		else {
			m_analyzer->Delete();
			return;
		}
	}
	HttpAnalyzerStream::Process(data);
}


/*!!!
			if (bRequest)
			{
				vector<String> words = (m_uri_full = header[0]).Split();
				if (words.size() >= 2)
				{
					vector<String> uri = words[1].Split("?", 2);
					if (uri.empty())
						goto exit;
					m_uri_base = uri[0];
					if ( uri.size() == 1)
						goto exit;	// There is no params
					vector<String> params = uri[1].Split("&");
					for (int i=params.size(); i--;)
					{
						vector<String> pair = params[i].Split("=", 2);
						if (pair.size() == 2)
						{
							m_uri[pair[0]] = pair[1];
							TRC(1, "*** URI param key: " << pair[0] << " value: " << pair[1]);
						}
					}
				}
			}
			*/
		

extern "C" {
class CHttpMessageAnalyzerClass : public CMessageAnalyzerClass {
public:
	CHttpMessageAnalyzerClass()
		: CMessageAnalyzerClass("HTTP")
	{
		Type = ATYPE_MANDATORY;
	}

	CMessageAnalyzer *CreateObject() { return new CMessageAnalyzer(new HttpAnalyzerClass); }

} g_httpMessageAnalyzerClass;
}

class WebAnalyzer : public CMessageAnalyzer, HttpSubscription {
	typedef map<String, DateTime> UriBaseMap;
	UriBaseMap m_uribase;

	void OnReceived(HttpDialog *dialog);
public:
	static WebAnalyzer *I;

	WebAnalyzer();

	~WebAnalyzer() 	{
		I = 0;
	}
};

class CWebMessageAnalyzerClass : public CMessageAnalyzerClass {
public:
	CWebMessageAnalyzerClass()
		:	CMessageAnalyzerClass("WEB")
	{
	}

	ptr<User> CreateUser() { return new WebUser; }

	CMessageAnalyzer *CreateObject() {
		Users.Load();
		return new WebAnalyzer;
	}
} g_webMessageAnalyzerClass;

WebMessage::WebMessage() {
	m_bPrint = false;
	m_analyzerClass = &g_webMessageAnalyzerClass;
}

static LruCache<pair<IPAddress, String> > s_LastUrls;

static wregex s_reLastSlash(String("://[^/]+(/)"));


void WebMessage::Finish() {
//	TRC(0, Text);

	String url = Text;
	Smatch m;
	if (regex_search(url, m, s_reLastSlash))
		url = url.Left(m.position(1));
	if (g_opt_LogLevel == 0) {
		Text = url;
	}
	if (s_LastUrls.insert(make_pair(ClientAddress, url)).second) {	
		m_bPrint = true;
#if UCFG_SNIF_PACKET_CAPTURE
		if (CTcpMan::s_bEnableLog) {
			String from = "someuser";
			if (From)
				from = From->ClientAddress.ToString();
			ofstream ofs((const char*)Path::Combine(g_webMessageAnalyzerClass.Dir, from+".txt"), ios::app);
			ofs << DateTime << '\t' << Text << endl;
		}
#endif
	} else if (g_opt_LogLevel == 0)
		return;
	base::Finish();
}

static wregex s_reBasic(String("^Basic\\s+(\\S+)")),
			s_reLoginPassword(String("([^:]+):([^:]+)")),
			s_reStartsAsUrl(String("^[a-zA-Z]+://"));

void WebAnalyzer::OnReceived(HttpDialog *dialog) {
	HttpDialog& d = *dialog; //!!!
	DateTime dt = ConnectionManager::I->m_dtLastPacket;
	String host = d.m_ci->DstEndPoint.Address.ToString();
	String shost = d.Request.Headers.Get("Host");
	if (!!shost)
		host = shost;
	String auth = d.Request.Headers.Get("Authorization");
	if (!!auth) {
		Smatch m;
		if (regex_search(auth, m, s_reBasic)) {
			Blob blob = Convert::FromBase64String(m[1]);
			String data = String((const char*)blob.constData(), blob.Size);
			if (regex_search(data, m, s_reLoginPassword))
				WebUser::GetByServerLogin(IPEndPoint(host), m[1])->SetPassword(m[2]);
		}
	}
	String url = d.Request.RequestUri;
	if (!regex_search(url, s_reStartsAsUrl))
		url = "http://"+host+url;
	ptr<WebMessage> webm = new WebMessage();
	webm->Text = url;
	webm->From = WebUser::GetByClientAddress(d.m_ci->SrcEndPoint.Address);
	webm->ClientAddress = d.m_ci->SrcEndPoint.Address;
	webm->Host = host;
	webm->Finish();
}

WebUser::WebUser() {
	g_webMessageAnalyzerClass.Users.AddInitial(this);
}

WebUser *WebUser::GetByServerLogin(const IPEndPoint& server, RCString login) {
  return static_cast<WebUser*>(g_webMessageAnalyzerClass.Users.GetByServerLogin(server, login).get());
}

WebUser *WebUser::GetByClientAddress(const IPAddress& ha) {
  return static_cast<WebUser*>(g_webMessageAnalyzerClass.Users.GetByClientAddress(ha).get());
}

WebAnalyzer *WebAnalyzer::I;

WebAnalyzer::WebAnalyzer()
	:	CMessageAnalyzer(nullptr)
{
	I = this;
}


} // Snif::


