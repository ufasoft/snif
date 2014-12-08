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


//!!!UserManager g_UserManager("users.xml");



CTraceCategory TRCAT_UM("UserManager");

bool g_opt_findbyip = true;

/*!!!
User::User(UserManager *users, RCString uid, const TcpStreamInfo &info)
{
	Users = users;
	D_TRACE(TRCAT_UM,1,"Adding user: " << uid);
	m_id = uid;
	AddServerIP(info.server_ip);
	AddClientIP(info.client_ip);
//!!!	UserManager::I().AddUser(this);
}

User::User(UserManager *users, RCString uid, uint client_ip, uint server_ip)
{
	Users = users;
	D_TRACE(TRCAT_UM,1,"Adding user2: " << uid);
	m_id = uid;
	AddServerIP(server_ip);
	AddClientIP(client_ip);
//!!!	UserManager::I().AddUser(this);
}

void User::AddNickname(RCString nick)
{
	m_nick = nick;
	Users->Save();
}
*/

void User::Log() {
	DateTime dt = ConnectionManager::I->m_dtLastPacket;
	String msg =g_opt_PrintAsDateTime ? dt.ToString() : dt.ToString(VAR_TIMEVALUEONLY);

	msg += "\t"+Users->m_analyzerClass.m_name+":\t";
	if (Server != IPEndPoint()) {
		String host = Server.ToString();
#if UCFG_SNIF_HOST_RESOLVE
		if (g_opt_ResolveEnabled)
			host = CHostResolver::Resolve(Server);
#endif
		msg += "\tServer: "+host+"\tLogin: "+Nick;
	} else
		msg += "\tLogin: "+Uid;
	if (!get_Password().IsEmpty())
		msg += "\tPassword: "+Password;
	LruLogMessage(msg);
}

void User::SetPassword(RCString s) {
	if (s != Password) {
		Password = s;
		CMsganTcpMan::I->OnUser(this);		
	}
}

void User::AddClientIP(const IPAddress& ip) {
	if (ip.IsEmpty())
		return;
	ClientAddress = ip;
//!!!	Users->AddMapping(ip, this);
}

void User::AddServerIP(const IPAddress& ip) {
	if (ip.IsEmpty())
		return;
	csip = ip;
	m_server_ip[ip] = true;
}

static regex s_reReplace("<|>|/|\\\\|:|\\||\\?|\"");

String AFXAPI User::ReplaceDisabledChars(RCString s) {
	Blob blob = Encoding::UTF8.GetBytes(s);
	string s1 = regex_replace(string((const char*)blob.constData(), blob.Size), s_reReplace, string("_"));
	return Encoding::UTF8.GetChars(ConstBuf(s1.data(), s1.size()));
}

String User::ToString() {
 	String r;
	if (!get_Nick().IsEmpty())
		r = Nick;
	if (!m_uid.IsEmpty())
		if (r.IsEmpty())
			r = m_uid;
		else
			r += "("+m_uid+")";
	if (r.IsEmpty() && !Email.IsEmpty())
		r += Email;
	if (r.IsEmpty()) {
		if (!MobilePhone.IsEmpty())
			r = "Phone: "+MobilePhone;
		else
			r = ClientAddress.ToString();
	}
#if UCFG_EXTENDED
	if ((DWORD)RegistryKey(AfxGetCApp()->KeyCU,"Options").TryQueryValue("LogIP",DWORD(0))) {
		r += "["+ClientAddress.ToString()+"]";
	}
#endif
	return r;
}

String User::ToDirName() {
	return ReplaceDisabledChars(ToString());

}

// XXX: !!!
User *User::FindByID(const char *uid)
{
	return NULL;
}

void UserManager::AddMapping(const IPAddress& ip, User *u) {
	if(u->Uid != "") {
		D_TRACE(TRCAT_UM,1,"* Mapping: add " << u->Uid << " at " << ip);
		m_mIp2User[ip] = u;
	}
}

User *UserManager::FindUserByIP(const IPAddress& ip) {
	TRC(1, "* FindByIP: " << ip);
	TIPUserMap::iterator u = m_mIp2User.find(ip);
	if (u == m_mIp2User.end())
		return 0;
	D_TRACE(TRCAT_UM, 1, "User found by IP " << u->second->Uid);
	return u->second;
}

User *UserManager::FindUserByID(RCString uid, const IPAddress& ip) {
	User *found = 0;
	for (size_t i=m_arUser.size(); i--;)
		if (m_arUser[i]->Uid == uid)
			found = m_arUser[i];
	if (!found) {
		if	(g_opt_findbyip && strlen(uid) == 0)
			found = FindUserByIP(ip);
		else
			return 0;	
	} else if (g_opt_findbyip && found->Uid == "")
			found = FindUserByIP(ip);
	return found;
}

User *UserManager::FindUserByNick(RCString nick, const IPAddress& ip) {
	User *found = 0;
	for (size_t i=m_arUser.size();i--;)
		if (m_arUser[i]->Nick == nick)
			found = m_arUser[i];
	if (found && g_opt_findbyip && !ip.IsEmpty() && found->Nick=="")
		found = FindUserByIP(ip);
	return found;
}

ptr<User> UserManager::GetByNick(RCString nick) {
	ptr<User> u = FindUserByNick(nick);
	if (!u)
		(u=m_analyzerClass.CreateUser())->m_nick = nick;
	return u;
}

ptr<User> UserManager::GetByClientAddress(const IPAddress& ha) {
	ptr<User> u;
	for (size_t i=m_arUser.size(); i--;)
		if (m_arUser[i]->ClientAddress == ha)
			u = m_arUser[i];
	if (!u)
		(u=m_analyzerClass.CreateUser())->ClientAddress = ha;
	return u;
}

ptr<User> UserManager::FindUserByPhone(RCString phone) {
	for (size_t i=m_arUser.size(); i--;)
		if (m_arUser[i]->MobilePhone == phone)
			return m_arUser[i];
	return nullptr;
}

ptr<User> UserManager::GetByServerLogin(const IPEndPoint& server, RCString login) {
	for (size_t i=m_arUser.size(); i--;) {
		ptr<User> u = m_arUser[i];
		if (u->Server==server && u->Nick==login)
			return u;
	}
	ptr<User> u = m_analyzerClass.CreateUser();
	u->Server = server;
	u->m_nick = login;
	return u;
}

void UserManager::AddInitial(User *u) {
	m_arUser.push_back(u);
	u->Users = this;
}

ptr<User> UserManager::Add(User *u) {
	User *test = FindUserByID(u->Uid);
	D_TRACE(TRCAT_UM,1,"AddUser: " << u->Uid);
	if (!test && u->Uid != "") {
		m_arUser.push_back(u);
		Save();
	}
	u->Users = this;
	return u;
}



/*!!!
UserManager *UserManager::s_pI;

UserManager::UserManager(RCString datafile)
	:	m_datafile(datafile),
	  m_bLoaded(false)
{
	s_pI = this;
}
*/

UserManager::~UserManager()
{
//!!!	Save(); because COM unloaded
//!!!	s_pI = 0;
#ifdef _X_DEBUG
		DumpList();
#endif
}

//!!!Rstatic wregex UserManager::s_reDb("(.*)\\t(.*)\\t(.*)\\t(.*)\\t(.*)\\t(.*)");

void UserManager::Load() {
	/*!!!D
	static const char s_xslt[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
														"<xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" version=\"1.0\">\n"
														"<xsl:output method=\"xml\" indent=\"yes\" encoding=\"UTF-8\"/>\n"
                            "<xsl:template match=\"@* | node()\">\n"
														"<xsl:copy>\n"
														"<xsl:apply-templates select=\"@* | node()\" />\n"
                            "</xsl:copy>\n"
														"</xsl:template>\n"
														"</xsl:stylesheet>";

	(MessageXslt = new XmlDocument).LoadXml(s_xslt);
	*/

#if UCFG_XML
	String datafile = Path::Combine(m_analyzerClass.Dir, "users.xml");

	if (FileInfo(datafile)) {

		ptr<XPathDocument> doc;
		try {
			doc = new XPathDocument(datafile);
		} catch (RCExc e) {
			cerr << e.Message << endl;
			goto out;
		} 
		ptr<XPathNavigator> nav = doc->CreateNavigator();
		ptr<XPathNodeIterator> users = nav->Select("/users/*");
		while (users->MoveNext()) { 
			ptr<XPathNavigator> user = users->Current;
			ptr<User> u = m_analyzerClass.CreateUser();

			u->Uid = user->GetAttribute("uid");
			u->m_dbID = atoi(user->GetAttribute("DBID"));
			String nick = user->GetAttribute("nick");
			u->m_nick = !nick.IsEmpty() ? nick : nullptr;
			if (ptr<XPathNavigator> n = user->SelectSingleNode("password"))
				u->Password = n->Value;
			if (ptr<XPathNavigator> n = user->SelectSingleNode("server"))
				u->Server = IPEndPoint(n->Value);
			if (ptr<XPathNavigator> n = user->SelectSingleNode("MobilePhone"))
				u->MobilePhone = n->Value;
			if (ptr<XPathNavigator> n = user->SelectSingleNode("client_ip"))
				u->ClientAddress = IPAddress::Parse(n->Value);
		}

/*!!!R

		XmlDocument dom = new XmlDocument;
		try {
			dom.Load(datafile);
		} catch (XmlException& e) {
			cerr << e.Message << " at line " << e.LineNumber << " in file " << datafile << "\nData discarded!" << endl;
			goto out;
		}
		XmlNodeList users = dom.SelectNodes("/users/*");
		TRC(1, m_analyzerClass.m_name << "\tLoading " << users.Count << " users");
		for (XmlElement user; user=users.NextNode();) {
			ptr<User> u = m_analyzerClass.CreateUser();
			u->Uid = user.GetAttribute("uid");
			u->m_dbID = atoi(user.GetAttribute("DBID"));
			String nick = user.GetAttribute("nick");
			u->m_nick = !nick.IsEmpty() ? nick : nullptr;
			if (XmlNode n = user.SelectSingleNode("password"))
				u->Password = n.InnerText;
			if (XmlNode n = user.SelectSingleNode("server"))
				u->Server = IPEndPoint(n.InnerText);
			if (XmlNode nodeMobile = user.SelectSingleNode("MobilePhone"))
				u->MobilePhone = nodeMobile.InnerText;
			if (XmlNode nodeIP = user.SelectSingleNode("client_ip"))
				u->ClientAddress = IPAddress::Parse(nodeIP.InnerText);
			*/

/*!!!R
			FOREACH(XmlNode,n,XmlNodeList,user.SelectNodes("client_ip"))
				u->AddClientIP(StrToHost(n.InnerText));
			FOREACH(XmlNode,n,XmlNodeList,user.SelectNodes("server_ip"))
				u->AddServerIP(StrToHost(n.InnerText));
			u->PostLoad();
			Add(u);
			*/
//!!!		}
	}
out:

#endif
	m_bLoaded = true;
}

void UserManager::Save() {
	EXT_LOCK (m_cs) {
		if (!m_bLoaded)
			return;
		DateTime now = DateTime::UtcNow();
		if (now-m_dtLastSave < TimeSpan::FromSeconds(10))
			return;
		m_dtLastSave = now;


	#if UCFG_XML
		if (!m_arUser.empty()) {
			ofstream os(Path::Combine(m_analyzerClass.Dir, "users.xml").c_str());
			XmlTextWriter w(os);
			w.Formatting = XmlFormatting::Indented;
			w.WriteStartDocument();
			XmlOut users(w, "users");

			for (int i=0; i<m_arUser.size(); i++) {
				ptr<User> u = m_arUser[i];
				XmlOut user(w, "user");
	//!!!D			user.SetAttribute("network",u->m_network);
				if (!u->get_Uid().IsEmpty())				
					user["uid"] = u->Uid;
				if (u->m_dbID)
					user["DBID"] = Convert::ToString(u->m_dbID);
				if (!u->m_nick.IsEmpty())
					user["nick"] = u->m_nick;
				if (!u->get_Password().IsEmpty()) {
					XmlOut x(w, "password");
					w.WriteString(u->Password);
				}
				if (!u->MobilePhone.IsEmpty()) {
					XmlOut x(w, "MobilePhone");
					w.WriteString(u->MobilePhone);
				}
				if (!(u->ClientAddress == IPAddress(0))) {
					XmlOut x(w, "client_ip");
					w.WriteString(u->ClientAddress.ToString());
				}
				for (User::TIPMap::iterator i = u->m_server_ip.begin(); i != u->m_server_ip.end(); i++) {
					XmlOut x(w, "server_ip");
					w.WriteString(i->first.ToString());
				}
				if (u->Server != IPEndPoint()) {
					XmlOut server(w, "server");
					if (u->Server.AddressFamily == AddressFamily::InterNetwork || u->Server.AddressFamily == AddressFamily::InterNetworkV6) {
	#ifdef WIN32
						String s = CHostResolver::Get().Resolve(u->Server.Address).ToString();
						if (!s.IsEmpty())
							server["domain"] = s;
	#endif
					}
					w.WriteString(u->Server.ToString());
				}
			}
		}
	#endif

	#if UCFG_SNIF_USE_OLEDB
		SaveToDb();
	#endif

			/*!!!R
		CDaoRecordset& rsU = ConnectionManager::I->m_rsUsers;
		if (rsU.IsOpen())
		{
			rsU.SetCurrentIndex("ID");
		}*/
	}
}


// Unit Testing
#ifdef _X_DEBUG

void UserManager::DumpList() {
	for (uint i=m_arUser.size();i--;) {
		User *u = m_arUser[i];
		cerr << " client_ip: " << u->ClientAddress << 
			" server_ip: " << u->server_ip() << 
			" id: " << u->m_id << " pass: " << u->Password << " nick: " << u->Nick << endl;
	}
}
#endif

} // Snif::
