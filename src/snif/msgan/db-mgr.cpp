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


#if UCFG_SNIF_USE_DB

DbThread::DbThread()
	:	Thread(&ConnectionManager::I->m_tr)
{
	m_bAutoDelete = false;
}

bool DbThread::Enqueue(Tasklet *tasklet) {
	if (!Failed) {
		EXT_LOCK (m_csQueue) {
			Queue.push(tasklet);
			m_ev.Set();
		}
		return true;
	}
	return false;
}

void DbThread::CreateDatabase() {
	if (m_bSqlite) {
		m_sqlite.Create(ConnString);

		TransactionScope dbtx(m_sqlite);

		m_sqlite.ExecuteNonQuery("PRAGMA page_size=8192");
		m_sqlite.ExecuteNonQuery(
			"CREATE TABLE Analyzers (id INTEGER PRIMARY KEY, name UNIQUE);"
			"CREATE TABLE Users (id INTEGER PRIMARY KEY, AnalyzerID, UID, Nick, Email, Password, Name);"
			"CREATE TABLE Messages (ID INTEGER PRIMARY KEY, AnalyzerID, DateTime, [From], [To], Text, SourceIP, DestIP);"
			"CREATE INDEX DateTime ON Messages (DateTime)"
			);
	}
#if UCFG_SNIF_USE_OLEDB
	else {
		try {
			m_db.CreateDatabase(ConnString);
		} catch (RCExc e) {
			cerr << e << endl;

			static regex s_reDatabaseName("Database=([^;]+)");
			string dbName = "Snif";
			Blob blob = Encoding::UTF8.GetBytes(ConnString);
			string s0((const char*)blob.constData(), blob.Size);
			cmatch m;
			if (regex_search(s0.c_str(), m, s_reDatabaseName)) {
				dbName = m[1];
			}		
			string s1 = regex_replace(string((const char*)blob.constData(), blob.Size), s_reDatabaseName, "");
			String newConnString =  Encoding::UTF8.GetChars(ConstBuf(s1.data(), s1.size()));

			m_db.Open(newConnString);
			m_db.Execute("CREATE DATABASE "+dbName);
			m_db.Execute("USE "+dbName);
		}
	}
#endif
}

void DbThread::OpenDatabase() {
	try {
#if UCFG_WIN32
		RegistryKey key(AfxGetCApp()->KeyCU, "Options");
		ConnString = key.TryQueryValue("DbConnstr", (LPCTSTR)CMsganTcpMan::GetDefaultDbConnstr());

		try {
			m_bSqlite = Path::GetExtension(ConnString).ToLower() == ".db";
		} catch (RCExc) {
		}

		InitCOM();
#endif
		
		cerr << "Opening database..." << endl;

		if (m_bSqlite) {
			if (File::Exists(ConnString))
				m_sqlite.Open(ConnString);
			else
				CreateDatabase();
			Enabled = true;
			return;
		}
#if UCFG_SNIF_USE_OLEDB
		try {
			DBG_LOCAL_IGNORE(E_FAIL);
			m_db.Open(ConnString);
		} catch (RCExc e) {
			cerr << e << endl;
			try {
				CreateDatabase();
			} catch (RCExc e) {
				cerr << e << endl;
				return;
			}
		}

		String sIdentity = "IDENTITY(1,1)";
		if (ConnString.ToUpper().Find("MYSQL") != -1)
			sIdentity = "AUTO_INCREMENT";

		try {
			DBG_LOCAL_IGNORE(DB_E_NOTABLE);
			ADODB::_RecordsetPtr rs;
			OleCheck(rs.CreateInstance(__uuidof(ADODB::Recordset)));
			rs->Open("Messages",_variant_t((IDispatch *)m_db.m_conn, true),ADODB::adOpenKeyset,ADODB::adLockOptimistic,ADODB::adCmdTable);
			try {
				rs->Fields->Item["SourceIP"];
			} catch (RCExc) {
				rs->Close();
				m_db.Execute("ALTER TABLE Messages ADD [SourceIP] varchar(40)"); //!!!D
				m_db.Execute("ALTER TABLE Messages ADD [DestIP] varchar(40)"); //!!!D
			}
//			m_db.EExecute("SELECT * FROM Messages");
			goto LAB_OPEN_RS;
		} catch (RCExc) {
			cerr << "Creating database structure..." << endl;
		}

		{
			String sqlCreateAnalyzers = "CREATE TABLE Analyzers("
									"ID int "+sIdentity+" PRIMARY KEY,"
									"Name varchar(255) UNIQUE"
								")",
					sqlCreateUsers = "CREATE TABLE Users("
									"ID int "+sIdentity+" PRIMARY KEY,"
									"AnalyzerID int,"
									"UID varchar(255),"
									"Nick varchar(255),"
									"Email varchar(255),"
									"[Password] varchar(255),"
									"Name varchar(255)"
								")",
					sqlCreateMessages = "CREATE TABLE Messages("
									"ID int "+sIdentity+" PRIMARY KEY,"
									"AnalyzerID int,"
									"[DateTime] datetime,"
									"[From] int,"
									"[To] int,"
									"[Text] ntext,"
									"[SourceIP] varchar(40),"
									"[DestIP] varchar(40)"
								")",
					sqlCreateIndexDateTime = "CREATE INDEX [DateTime] ON Messages ([DateTime])";
			
			if (ConnString.ToUpper().Find("MYSQL") != -1) {
				sqlCreateAnalyzers.Replace("[", "`");
				sqlCreateAnalyzers.Replace("]", "`");
				sqlCreateUsers.Replace("[", "`");
				sqlCreateUsers.Replace("]", "`");
				sqlCreateMessages.Replace("[", "`");
				sqlCreateMessages.Replace("]", "`");
				sqlCreateMessages.Replace("ntext", "varchar(255)");
				sqlCreateIndexDateTime.Replace("[", "`");
				sqlCreateIndexDateTime.Replace("]", "`");
			}

			m_db.Execute(sqlCreateAnalyzers);
			m_db.Execute(sqlCreateUsers);
			m_db.Execute(sqlCreateMessages);
			m_db.Execute(sqlCreateIndexDateTime);
		}
LAB_OPEN_RS:
		OleCheck(m_rsUsers.CreateInstance(__uuidof(ADODB::Recordset)));
		m_rsUsers->Open("Users",_variant_t((IDispatch *)m_db.m_conn, true),ADODB::adOpenKeyset,ADODB::adLockOptimistic,ADODB::adCmdTable);

		OleCheck(m_rsMessages.CreateInstance(__uuidof(ADODB::Recordset)));
		m_rsMessages->Open("Messages",_variant_t((IDispatch *)m_db.m_conn, true),ADODB::adOpenKeyset,ADODB::adLockOptimistic,ADODB::adCmdTable);
#endif
		Enabled = true;
	} catch (RCExc e) {
		Failed = true;
		cerr << e << endl;
	}

}

void DbThread::EnsureTransactionStarted() {
	if (!exchange(m_dbTxBegin, true))
		m_sqlite.ExecuteNonQuery("BEGIN TRANSACTION");
}

void DbThread::CommitTransactionIfStarted() {
	if (exchange(m_dbTxBegin, false))
		m_sqlite.ExecuteNonQuery("COMMIT");
}

void DbThread::Execute() {
	OpenDatabase();
	if (Enabled) {
		while (!m_bStop) {
			while (true) {
				ptr<Tasklet> tasklet;
				EXT_LOCK (m_csQueue) {
					if (!Dequeue(Queue, tasklet))
						break;
				}
				try {
					EnsureTransactionStarted();
					tasklet->Execute();
				} catch (RCExc e) {
					cerr << e << endl;
				}
				tasklet->EvComplete.Set();
			}
			CommitTransactionIfStarted();
			m_ev.Lock();
		}
	}
}


class ActivateAnalyzerClassTasklet : public Tasklet {
	void Execute() override {
		DbThread& t = *ConnectionManager::I->DbThread;
		if (t.m_bSqlite) {
			SqliteCommand cmd("SELECT ID FROM Analyzers WHERE Name=?", t.m_sqlite);
			cmd.Bind(1, AnalyzerClass->m_name);
			try {
				DBG_LOCAL_IGNORE(E_INVALIDARG);
				AnalyzerClass->m_dbID = cmd.ExecuteInt64Scalar();
			} catch (RCExc) {
				SqliteCommand("INSERT INTO Analyzers(Name) VALUES(?)", t.m_sqlite)
					.Bind(1, AnalyzerClass->m_name)
					.ExecuteNonQuery();
				AnalyzerClass->m_dbID = t.m_sqlite.LastInsertRowId;
			}
		}
#if UCFG_SNIF_USE_OLEDB
		else {
			OleDbConnection& db = t.m_db;
			String sql = "SELECT ID FROM Analyzers WHERE Name="+SqlQuotate(AnalyzerClass->m_name);
			try {
				DBG_LOCAL_IGNORE(MAKE_HRESULT(SEVERITY_ERROR, FACILITY_CONTROL, ADODB::adErrNoCurrentRecord));
				AnalyzerClass->m_dbID = Convert::ToInt32(db.ExecuteScalar(sql));
			} catch (RCExc) {
				db.Execute("INSERT INTO Analyzers(Name) VALUES("+SqlQuotate(AnalyzerClass->m_name)+")");
				AnalyzerClass->m_dbID = Convert::ToInt32(db.ExecuteScalar(sql));
			}
		}
#endif
	}
public:
	CMessageAnalyzerClass *AnalyzerClass;
};

void CMessageAnalyzerClass::DbActivate() {
	if (ConnectionManager::I->DbThread) {
		ptr<ActivateAnalyzerClassTasklet> tl = new ActivateAnalyzerClassTasklet;
		tl->AnalyzerClass = this;
		ConnectionManager::I->DbThread->Enqueue(tl);
	}
}

class MessageTasklet : public Tasklet {
public:
	ptr<Snif::Message> Message;
protected:
	void Execute() override {
		String text;
#	if UCFG_USELISP
		text = Convert::ToString(CLispHelper::I().Call("MY-STRING-VAL", Message->Text));
#	else
		text = Message->Text;
#	endif

		if (ConnectionManager::I->DbThread->m_bSqlite) {
			SqliteCommand cmd("INSERT INTO messages (AnalyzerID, DateTime, [From], SourceIP, [To], DestIP, Text) VALUES (?, ?, ?, ?, ?, ?, ?)", ConnectionManager::I->DbThread->m_sqlite);
			cmd.Bind(1, Message->m_analyzerClass->m_dbID);
			cmd.Bind(2, Message->DateTime.UnixEpoch);
			if (Message->From) {
				if (Int32 dbId = Message->From->GetDBID())
					cmd.Bind(3, dbId);
				else
					cmd.Bind(3, nullptr);
				cmd.Bind(4, Message->From->ClientAddress.ToString());
			} else {
				cmd.Bind(3, nullptr);
				cmd.Bind(4, nullptr);
			}
			if (Message->To) {
				if (Int32 dbId = Message->To->GetDBID())
					cmd.Bind(5, dbId);
				else
					cmd.Bind(5, nullptr);
				cmd.Bind(6, Message->To->ClientAddress.ToString());
			} else {
				cmd.Bind(5, nullptr);
				cmd.Bind(6, nullptr);
			}
			cmd.Bind(7, text);
			cmd.ExecuteNonQuery();
		}
#	if UCFG_WIN32
 		else {
			CBag bagF, bagV;

			bagF.Add("AnalyzerID");
			bagV.Add(Message->m_analyzerClass->m_dbID);

			bagF.Add("DateTime");
			bagV.Add(Message->DateTime);

			if (Message->From) {
				if (Int32 dbId = Message->From->GetDBID()) {
					bagF.Add("From");
					bagV.Add(dbId);
				}

				bagF.Add("SourceIP");
				bagV.Add(Message->From->ClientAddress.ToString());
			}

			if (Message->To) {
				if (Int32 dbId = Message->To->GetDBID()) {
					bagF.Add("To");
					bagV.Add(dbId);
				}

				bagF.Add("DestIP");
				bagV.Add(Message->To->ClientAddress.ToString());
			}

			bagF.Add("Text");
			bagV.Add(COleVariant(text));

			ConnectionManager::I->DbThread->m_rsMessages->AddNew(COleVariant(bagF), COleVariant(bagV));
//			rs->Update();
		}
#	endif

	}
};

void Message::DbFinish() {
	if (ConnectionManager::I->DbThread) {
		ptr<MessageTasklet> tl = new MessageTasklet;
		tl->Message = this;
		ConnectionManager::I->DbThread->Enqueue(tl);
	}
}

void User::SaveToDB() {
	if (!Dirty)
		return;
	try {
		if (!m_dbID) {
			GetDBID();
			return;
		}

		if (ConnectionManager::I->DbThread->m_bSqlite) {
			SqliteCommand cmd(EXT_STR("UPDATE users SET UID=?, Nick=?, Password=?, Email=? WHERE id=" << m_dbID), ConnectionManager::I->DbThread->m_sqlite);
			if (!m_uid.IsEmpty())
				cmd.Bind(1, m_uid);
			else
				return;
			if (!m_nick.IsEmpty())
				cmd.Bind(2, m_nick);
			else
				cmd.Bind(2, nullptr);
			if (!get_Password().IsEmpty())
				cmd.Bind(3, Password);
			else
				cmd.Bind(3, nullptr);
			String server = Server==IPEndPoint() ? "" : Server.ToString();
			if (!Email.IsEmpty() || !server.IsEmpty()) {
				String email = Email;
				if (email.IsEmpty())
					email = server;
				cmd.Bind(4, email);
			} else
				cmd.Bind(4, nullptr);
			cmd.ExecuteNonQuery();
		}
#if UCFG_WIN32
		else {
			CBag bagF, bagV;
			if (!m_uid.IsEmpty()) {
				bagF.Add("UID");
				bagV.Add(COleVariant(m_uid));
			} else
				return;
			if (!m_nick.IsEmpty()) {
				bagF.Add("Nick");
				bagV.Add(COleVariant(m_nick));
			}
			if (!Password.IsEmpty()) {
				bagF.Add("Password");
				bagV.Add(Password);
			}
			String server = Server==IPEndPoint() ? "" : Server.ToString();
			if (!Email.IsEmpty() || !server.IsEmpty()) {
				String email = Email;
				if (email.IsEmpty())
					email = server;
				bagF.Add("Email");
				bagV.Add(email);
			}
			if (bagF.Count) {
				ADODB::_RecordsetPtr rs;
				OleCheck(rs.CreateInstance(__uuidof(ADODB::Recordset)));
				String sreq = "SELECT * FROM Users WHERE ID="+Convert::ToString(m_dbID);
				rs->Open(sreq.Bstr, _variant_t((IDispatch *)ConnectionManager::I->DbThread->m_db.m_conn, true), ADODB::adOpenStatic, ADODB::adLockOptimistic, ADODB::adCmdText);
				rs->Update(COleVariant(bagF), COleVariant(bagV));
			}
		}
#endif
	} catch (RCExc e) {
		cerr << e << endl;
	}
	Dirty = false;
}

LONG User::AddNewToDB() {
	DbThread& t = *ConnectionManager::I->DbThread;
	if (t.m_bSqlite) {
		SqliteCommand(EXT_STR("INSERT INTO users (AnalyzerID) VALUES (" << Users->m_analyzerClass.m_dbID << ")"), t.m_sqlite).ExecuteNonQuery();
		m_dbID = t.m_sqlite.LastInsertRowId;
	}
#if UCFG_WIN32
	else {
		CBag bagF, bagV;
		bagF.Add("AnalyzerID");
		bagV.Add(Users->m_analyzerClass.m_dbID);
		t.m_rsUsers->AddNew(COleVariant(bagF), COleVariant(bagV));
		m_dbID = Convert::ToInt32(t.m_rsUsers->Fields->Item["ID"]->Value);
	}
#endif

	SaveToDB();
//		rsU.Update();
	return m_dbID;
}

Int32 User::GetDBID() {
	if (!m_dbID && !m_uid.IsEmpty())
		AddNewToDB();
	return m_dbID;
}

class SaveUsersTasklet : public Tasklet {
public:
	vector<ptr<User> > m_arUser;
protected:
	void Execute() {
		for (int i=0; i<m_arUser.size(); i++)
			m_arUser[i]->SaveToDB();
	}
};

void UserManager::SaveToDb() {
	if (ConnectionManager::I->DbThread) {
		ptr<SaveUsersTasklet> tl = new SaveUsersTasklet;
		tl->m_arUser = m_arUser;
		ConnectionManager::I->DbThread->Enqueue(tl);
	}
}

#endif

} // Snif::


