/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "msgan.h"
#include "packetwriter.h"


#if UCFG_USELISP

class IcqDumpOutputStream : public OutputStream {
	void put(wchar_t ch) override {
		wcout.put(ch);
	}
public:
	IcqDumpOutputStream()
		:	OutputStream(stdout)
	{}
};

#endif

class CIcqDumpProtoEng : public CMsganTcpMan {
public:
	~CIcqDumpProtoEng() {
		ConnectionManager::CloseAll();
	}


	//	WebAnalyzer m_wa;
	void PrintUsage() {
		cerr << "\n"
			"Usage: icqdump [options] [expression]\n"
			"Options:\n"
#ifdef WIN32
			"  -A  enable arp-spoofing:\n"
			"     all: for all available network hosts\n"
			"     no: disable ARPSPOOF subprocess\n"
			"     ip[,ip,..]: for only selected hosts\n"
#endif
			"  -B Free Using\n"
			"  -E <format>\tselect format of mailbox, can be UNIX (default), EUDORA\n"
			"  -e <codepage> select codepage for output, can be ANSI, OEM, UNICODE, UTF8 or number\n"
			"  -f Save Transferred Files (FTP/SMB/ICQ)\n"
			"  -m <codepage> Message codepage for 8-bit messages\n"
			"  -n don't resolve IPs to Domain Names & UINs to NickNames via Web\n"
			"  -D list interfaces\n"
			"  -h print this help message\n"
			"  -i <iface>\tnetwork interface number to listen to\n"
			"  -k <wep-key>\tWEP key as 10(40-bit WEP) or 26(104-bit WEP) hexadecimal digits. Can be repeated multiple times\n"
			"  -l <dir>\tchange Log directory\n"
			"  -P <protocol>\tprotocol, may be ICQ, IRC, MSN, Yahoo, EMail, Search, mail.ru, vkontakte.ru, "
#if UCFG_WIN32
"mamba.ru, "
#endif
"FTP, SMB or ALL. By default all of them\n"
			"  -q Don't show CrashMessageBox\n"
			"  -tttt  Print timestamp as Date/Time\n"
			"  -v <logLevel> Set LogLevel (default 1)\n"
			"  -z try to resolve user by ip address\n"
			//!!!			"  -w\t\twrite every captured packet to the file traffic.dat (for debugging)\n"
			"  -x\t\twrite captured messages as xml\n"
			"    (all available interfaces are included by default)\n"
			"  -r <file>\tread packets from file, stored with tcpdump -s0 -w options\n"
			"  expression: tcpdump-like filtering expression\n"
			"\nSee the Help for additional information\n" << endl;
	}
};

class PacketWriter;

void MyLogMessage(RCString s) {
	String ss = s;
	ss.Replace("\a", " ");	// replace BELL chars
#if UCFG_USELISP
	static CP fun = CLispHelper::I().m_lisp->VGetSymbol("MY-PRINT");
	CLispHelper::I().Call(fun, ss);
#else
	wcout << ss << endl;
#endif
}

void MyErrMessage(RCString s) {
	wcerr << s << endl;
}

#if UCFG_WIN32 && defined(UCFG_HEAP_CHECK)
#	include <tcmalloc/gperftools/heap-checker.h>
#endif


CIcqDumpProtoEng *g_pIcqDumpProtoEng;

class CIcqDumpApp : public CConApp {
	bool OnSignal(int sig) {
		if (g_pIcqDumpProtoEng)
			g_pIcqDumpProtoEng->BreakLoop();
		CConApp::OnSignal(sig);
		return true;
	}

	int ExitInstance() {
		return CConApp::ExitInstance();
	}

	void Execute()  override {
		Encoding::SetThreadIgnoreIncorrectChars(true);		//!!!

#if UCFG_USE_POSIX
		Environment::SetEnvironmentVariable("GCONV_PATH", Path::Combine(Path::GetDirectoryName(System.ExeFilePath), "gconv"));
#endif


#ifdef X_DEBUG//!!!D
		{
			DateTime now = DateTime::UtcNow();		//!!!D
			struct tm t = now;
			cerr << now << "\t" << t.tm_hour << endl;
			Encoding enc(1251);
			char str[128];
			for (int i=0; i<128; i++)
				str[i] = i+128;
			String s(enc, str+0x40, 3);
			cerr << s << endl;
			exit(1);
		}
#endif




#ifdef WIN32
		InitCOM();
#endif

#if UCFG_HEAP_CHECK
		HeapLeakChecker check("noleaks2");
#endif
		{
			CIcqDumpProtoEng g_icqDumpProtoEng;
			g_pIcqDumpProtoEng = &g_icqDumpProtoEng;

	//		CTrace::s_nLevel = 0; // default
			TRCAT_UM.Enabled = false; //!!!
			TRCAT_HTTP.Enabled = false;
			TRCAT_P.Enabled = false;

	#if !UCFG_SNIF_USE_PCAP
	//!!!		CLocalSnifEng::s_StartInSeparateThread = false;
	#endif
			g_icqDumpProtoEng.MakeMain();
			//		PacketWriter g_PacketWriter;


			g_opt_ResolveEnabled = 1;
	#ifdef _WIN32
			g_opt_ResolveEnabled = (DWORD)RegistryKey(AfxGetCApp()->KeyCU, "Options").TryQueryValue("ResolveEnabled", g_opt_ResolveEnabled);
	#endif

			g_icqDumpProtoEng.ParseCommandLine();

			if (g_codepage) {
#ifdef _WIN32 //!!!?
				if (g_codepage != CODEPAGE_UNICODE) {						//!!!?
					locale loc(locale(), new CodepageCvt(g_codepage));
					wcout.imbue(loc);
					wcerr.imbue(loc);
				}
#endif
			} else {
#ifdef _WIN32 //!!!?
				locale loc(locale(), new CodepageCvt(CP_UTF8));
				wcout.imbue(loc);
				wcerr.imbue(loc);
#endif

#ifdef WIN32
				locale locOem(locale(), new CodepageCvt(CP_OEMCP));
				if (_isatty(_fileno(stdout)))
					wcout.imbue(locOem);
				if (_isatty(_fileno(stderr)))
					wcerr.imbue(locOem);
#endif
			}


	#if UCFG_USELISP
			CLispHelper::I().m_lisp->Streams[STM_StandardOutput] = new IcqDumpOutputStream;
	#endif

			MyErrMessage("Saving logs to: " +CProtoEng::s_pMain->m_sLogDir);


			//!!!		UserManager::I().Load();
			//!!!		UserManager::I().Create();

			vector<ptr<CMessageAnalyzer>> ar;

	#if defined(_X_DEBUG)// |defined(_PROFILE) //!!!D
			cout << "Debugging..." << endl;
			TestUnit testing(Path::Combine(CProtoEng::s_pMain->m_sLogDir,"tests"));
			testing.EudoraWriter("Eudora", "Snifmail");
			//!!!		testing.SingleParse(&g_icqDumpProtoEng, "email");

	#endif

			g_icqDumpProtoEng.m_cm.Start();

	#ifdef WIN32
			if (CUpgradeBase::I->AutoGetwork)
				CUpgradeBase::I->StartWorking();
	#endif


			g_icqDumpProtoEng.Loop(TimeSpan::MaxValue);
		}

#if UCFG_HEAP_CHECK
		check.BriefNoLeaksWithSym();
		LogObjectCounters();
#endif

		TRC(0, "End");
	}
public:
	CIcqDumpApp() {
#	ifdef _DEBUG
    	try {
			//!!! static ofstream ofs("trace.log");
    	} catch (RCExc) {
		}


		

//    	_crtBreakAlloc = 991;
    	//_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
//		_CrtSetDumpClient(MyDumpClient);
#	endif


		PLogMessage = &MyLogMessage;
	}	
} theApp;


EXT_DEFINE_MAIN(theApp)

