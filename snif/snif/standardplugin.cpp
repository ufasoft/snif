/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#if UCFG_UPGRADE
#	include <el/comp/upgrade.h>
#endif

#include "standard-plugin.h"

extern "C" {
//	#include "interface.h"
}

#if UCFG_EXTENDED
CWinApp theApp;
#endif

#if UCFG_GUI
#	include "plugin-gui.h"
#endif

namespace Snif {

IMPLEMENT_DYNCREATE(SnifferPlugin,Object)

#if UCFG_GUI

void WpcapExportResources() {
	static CDynLinkLibrary *s_dll = new CDynLinkLibrary(AfxGetStaticModuleState()->m_hCurrentInstanceHandle);
}

void SnifferPlugin::CreateConditionsView() {
	if (m_pViewClass) {
		m_pView = (CConditionsView*)m_pViewClass->CreateObject();
		m_pView->m_pPlugin = this;
	}
}
#endif	

bool SnifferPlugin::CheckConditions(PluginPacket *iPacket) {
#if !UCFG_SNIF_USE_ODDB
	return true;
#else
	return m_obCond ? Convert::ToBoolean(m_obCond.GetProperty("All")) : true;
#endif
}

class PPPObj;

void SnifferPlugin::ProcessSubAnalyzers(PluginPacket *iPacket) {
	if (AnalyzerBinder::Map *m = GetProtocolMap()) {
		long proto = iPacket->GetProto(); //!!! may be error
#ifdef X_DEBUG//!!!D
		static int s_n;
		++s_n;
		if (s_n >= 612430) {
			iPacket->GetProto();
			proto = proto;
		}
#endif
		
#ifdef X_DEBUG//!!!D
		for (AnalyzerBinder::Map::iterator it=m->begin(); it!=m->end(); ++it) {
			int pr = it->first;
			AnalyzerBinder::Subscribers& subs = it->second;
		}
#endif
		AnalyzerBinder::Map::iterator i = m->find(proto);
		if (i != m->end()) { 
			AnalyzerBinder::Subscribers& subs = i->second;
			for (AnalyzerBinder::Subscribers::iterator j=subs.begin(); j!=subs.end(); ++j)
				(*j)->Analyze(iPacket);
		}
	}
}

void SnifferPlugin::ProcessPacket(PluginPacket *iPacket) {
	//!!!  iSP->SetLayer((BYTE)m_layer);
#if UCFG_SNIF_USE_ODDB
	if (m_obCond && Convert::ToBoolean(m_obCond.GetProperty("Save"))) {
		SnifferPacket *iSP = iPacket->GetRootPacket();
		iSP->Save(m_clPacket);
		COdObject ob = iSP->GetODObject();
		m_collPackets.Add(ob);
	}
#endif
	ProcessSubAnalyzers(iPacket);
}

#if UCFG_SNIF_USE_ODDB
void SnifferPlugin::DefinePluginClasses(COdClass& clCond) {
}

void SnifferPlugin::SetDefaultConditions() {
	COdObject(AsUnknown(m_obj.GetProperty("Conditions"))).SetProperty("All", COleVariant(true));
	COdObject(AsUnknown(m_obj.GetProperty("Conditions"))).SetProperty("Save", COleVariant(true));
}

void SnifferPlugin::UpgradePluginClasses(COdClass& clCond) {
}

COdObject FindGlobal(COdDatabase db, RCString name) {
	CVariantIterator vi(db.GlobalObjects);
	for (COleVariant v; vi.Next(v);) {
		COdObject ob(AsUnknown(v));
		if (Convert::ToString(ob.GetProperty("Name")) == name)
			return ob;
	}
	return COdObject();
}

#endif

SnifferPlugin::SnifferPlugin()
	: 
#if UCFG_GUI
	m_pViewClass(RUNTIME_CLASS(CConditionsView)),
#endif
	m_bMacPlugin(false)
{
}

void SnifferPlugin::Bind() {
	m_binder->m_map[m_layer].insert(this);
}

void SnifferPlugin::UnbindPlugin() {
	m_binder->m_map[m_layer].erase(this);
}

void SnifferPlugin::AnalyzeCreated(PluginPacket *iPP) {
	iPP->PreAnalyze();
	if (CheckConditions(iPP))
		ProcessPacket(iPP);
}

void SnifferPlugin::AnalyzeCreated(PluginPacket& pp, SnifferPacketBase *iPacket) {
	pp.InitInStack(this, iPacket);
	AnalyzeCreated(&pp);
}

void SnifferPlugin::Analyze(SnifferPacketBase *iPacket) {
	ptr<PluginPacket> iNew = CreatePacket(iPacket);
	AnalyzeCreated(iNew);
}

void SnifferPlugin::Reanalyze(SnifferPacketBase *iPacket) {
	return Analyze(iPacket);
}

#if UCFG_GUI
void SnifferPlugin::Connect(SnifferSite *pSite) {
	m_iSite = pSite;
	COdDatabase db = pSite->GetDatabase();
	if (db) {
		m_clPacket = db.Classes["Packet"];
		if (!(m_obj = FindGlobal(db, m_name))) {
			db.Workspace.EnsureBeginTrans();
			COdClass cl = db.CreateClass(m_name),
				clCond = db.CreateClass(m_name + "Conditions");
			cl.CreateField("Version", "int");
			cl.CreateField("Name", "string");
			cl.CreateField("Conditions", LPCTSTR(m_name + "Conditions")).Optional = false;
			cl.CreateField("Packets", "Packet *[]");
			m_obj = cl.CreateObject();      

			clCond.CreateField("All", "boolean");
			clCond.CreateField("Save", "boolean");
			DefinePluginClasses(clCond);

			m_obj.SetProperty("Version", COleVariant(1L));
			m_obj.SetProperty("Name", COleVariant(m_name));
			SetDefaultConditions();
			db.GlobalObjects.Add(m_obj, m_name);
			db.Workspace.EnsureCommitTrans();
		} else
			UpgradePluginClasses(db.Classes[m_name + "Conditions"]);
		m_obCond = COdObject(AsUnknown(m_obj.GetProperty("Conditions")));
		m_collPackets = m_obj.GetProperty("Packets");
	}
}

vector<String> SnifferPlugin::GetDataSets() {
	vector<String> vec;
	vec.push_back("Packets");
	return vec;
}

HWND SnifferPlugin::ShowFilter(HWND hwnd) {
	CreateConditionsView();
	CWnd *pWndPar = CWnd::FromHandle((HWND)hwnd);
	m_pView->Create(nullptr, nullptr,WS_CHILD | WS_BORDER, Ext::Rectangle(0,0,0,0),pWndPar,1,0);
	m_pView->UpdateData(false);
	return (HWND)*m_pView;
}

void SnifferPlugin::HideFilter() {
	m_pView->Destroy();
}

ptr<DataSet> SnifferPlugin::GetDataSet(RCString name) {
	if (name != "Packets")
		Throw(E_EXT_ItemNotFound);
	if (!m_pDataSet)
		m_pDataSet = new PacketDataSet(this);
	return m_pDataSet;
}

ptr<Object> PacketDataSet::GetItem(int idx) {
	return m_plugin->m_iSite->ProcessPacket(SnifferPacket::Load(m_plugin->m_collPackets.GetItem(idx)));
}

size_t PacketDataSet::GetCount() {
	return m_plugin->m_collPackets.Count;
}

vector<String> PacketDataSet::GetFields() {
	vector<String> ar;
	ar.push_back("Order");
	ar.push_back("Timestamp");
	ar.push_back("Length");
	/*!!!  ar.Add("Source");
	ar.Add("Destination");*/
	ar.push_back("Summary");
	return ar;
}

IMPLEMENT_DYNCREATE(CConditionsView, CFormView)

BEGIN_MESSAGE_MAP(CConditionsView, CFormView)
	ON_BN_CLICKED(CB_SAVE, &CConditionsView::OnClickSave)
	ON_BN_CLICKED(CB_ALL, &CConditionsView::OnClickAll)
END_MESSAGE_MAP()

void CConditionsView::DoDataExchange(CDataExchange* pDX) {
	CFormView::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CConditionsView)
	DDX_Control(pDX, CB_SAVE, m_cbSave);
	DDX_Control(pDX, CB_ALL, m_cbAll);
	//}}AFX_DATA_MAP
	if (!pDX->m_bSaveAndValidate) {
		m_cbSave.Check = Convert::ToInt32(m_pPlugin->m_obCond.GetProperty("Save"));
		m_cbAll.Check = Convert::ToInt32(m_pPlugin->m_obCond.GetProperty("All"));
	}
}

void CConditionsView::OnClickAll() {
	m_pPlugin->m_obCond.SetProperty("All", COleVariant((long)m_cbAll.Check));
}

void CConditionsView::OnClickSave() {
	m_pPlugin->m_obCond.SetProperty("Save", COleVariant((long)m_cbSave.Check));
}



#endif

void SnifferPlugin::Disconnect() {
#if UCFG_GUI
	m_iSite = nullptr;
#endif
}

/*!!!
void SnifferPlugin::Subscribe(SnifferPlugin *anObj, long prot)
{
CSubscription s;
s.m_iSubscription = anObj;
s.m_proto = prot;
m_arSubscribers.push_back(s);
}

void SnifferPlugin::Unsubscribe(SnifferPlugin *anObj)
{
for (int i=0; i<m_arSubscribers.size(); i++)//!!!
if (m_arSubscribers[i].m_iSubscription == anObj)
{
m_arSubscribers.erase(m_arSubscribers.begin()+i);
break;
}
}
*/


void SnifferPlugin::Clear() {
#if UCFG_SNIF_USE_ODDB
	m_collPackets.DeleteAll();
#endif
}

ptr<PluginPacket> SnifferPlugin::CreateSubPluginPacket(ptr<PluginPacket> iNew) {
	if (AnalyzerBinder::Map *m = GetProtocolMap()) {
		long proto = iNew->GetProto(); //!!! may be not OK
		AnalyzerBinder::Map::iterator i = m->find(proto);
		if (i != m->end()) {
			AnalyzerBinder::Subscribers& subs = i->second;
			for (AnalyzerBinder::Subscribers::iterator j=subs.begin(); j!=subs.end(); ++j) {
				if (ptr<PluginPacket> iPP = (*j)->CreatePluginPacket(iNew))
					return iPP;
			}
		}
	}

	/*!!!
	for (int i=0; i<m_arSubscribers.size(); i++)
	{
	CSubscription& s = m_arSubscribers[i];
	ptr<PluginPacket> iPP;
	if (s.m_proto == proto)
	iPP = s.m_iSubscription->CreatePluginPacket(iNew);
	if (iPP)
	return iPP;
	}*/
	return iNew;
}

ptr<PluginPacket> SnifferPlugin::CreatePluginPacket(SnifferPacketBase *iSP) {
	ptr<PluginPacket> iNew = CreatePacket(iSP);
	iNew->PreAnalyze();

	return CreateSubPluginPacket(iNew);
}

#if UCFG_OLE
void SnifferPlugin::GetProps(CBag& bag) {
	bag.Add(CBag(m_layer));
	CBag sbag;
	vector<long> prov = GetProvided();
	for (int i=0; i<prov.size(); i++)
		sbag.Add(prov[i]);
	bag.Add(sbag);
}

void PluginPacket::AddFieldInfo(CBag& bag, RCString s, ssize_t beg, ssize_t len) {
	bag.Add((CBag(s),COleVariant(),COleVariant(long(beg+GetOffset())),COleVariant(long(len))));
}

void PluginPacket::Info(CBag& bag) {
	if (!m_iBase->IsSnifferPacket())
		StaticCast<PluginPacket>(m_iBase)->Info(bag);
}

#endif

ptr<PluginPacket> SnifferPlugin::CreatePacket(SnifferPacketBase *iSPB) {
	if (m_pPacketClass) {
		ptr<PluginPacket> pp = (PluginPacket*)m_pPacketClass->CreateObject();
		pp->m_pPlugin = this;
		pp->m_iBase = iSPB;
		return pp;
	}
	return nullptr;
}

ITcpdumpHook *ITcpdumpHook::I;

IMPLEMENT_DYNAMIC(PluginPacket, Object)

String PluginPacket::GetField(RCString fieldID) {
	String r;
	String name = fieldID;
	/*!!!D
	if (name == "Summary") {
	} else*/
	{
		if (!m_iBase->IsSnifferPacket())
			return StaticCast<PluginPacket>(m_iBase)->GetField(fieldID);
		ILP_SnifferPacket iSP = StaticCast<SnifferPacket>(m_iBase);
		if (name == "Order")
			r = Convert::ToString(iSP->Order);
		else if (name == "Timestamp")
			r = iSP->TimeStamp.ToLocalTime().ToString(Microseconds());
		else if (name == "Length")
			r = Convert::ToString((int)iSP->Size);
		else if (name == "Summary")
			r = ITcpdumpHook::I->Process(iSP);
		else
			Throw(E_EXT_ItemNotFound);
	}
	return r;
}

Buf PluginPacket::GetData() {
	long off = GetLocalDataOffset();
	Buf mb = m_iBase->GetData();
	mb.P += off;
	if (int(mb.Size-=off) < 0)
		Throw(E_Sniffer_BadPacketFormat);
	return mb; //!!! need to check len
}

const byte *PluginPacket::GetChunk(int pos, int size) {
	Buf mb = m_iBase->GetData();
	if (pos+size > mb.Size)
		Throw(E_Sniffer_BadPacketFormat);
	return mb.P+pos;
}

void PluginPacket::SetChunk(int pos, const ConstBuf& chunk) {
	Buf mb = m_iBase->GetData();
	if (pos+chunk.Size > mb.Size)
		Throw(E_Sniffer_BadPacketFormat);
	memcpy(mb.P+pos, chunk.P, chunk.Size);
}

int PluginPacket::GetOffset() {
	if (m_iBase->IsSnifferPacket())
		return 0;
	return StaticCast<PluginPacket>(m_iBase)->GetDataOffset();
}

int PluginPacket::GetLocalDataOffset() {
	return 0;
}


ILP_SnifferPacket PluginPacket::GetRootPacket() {
	if (m_iBase) {
		return m_iBase->IsSnifferPacket() ? ILP_SnifferPacket(static_cast<SnifferPacket*>(m_iBase.get())) : m_iBase->GetRootPacket();
	}
	return nullptr;
}

ptr<PluginPacket> PluginPacket::MakePacketHeaped() {
	ptr<PluginPacket> r = IsHeaped() ? this : Clone();

	if (r->m_iBase) {
		if (r->m_iBase->IsSnifferPacket()) {
			if (!r->m_iBase->IsHeaped())
				r->m_iBase = SnifferPacket::FromSnifPacket(*static_cast<SnifferPacket*>(r->m_iBase.get()));
		} else
			r->m_iBase = (SnifferPacketBase*)((PluginPacket*)r->m_iBase.get())->MakePacketHeaped().get();			//!!! Casts
	}
	r->PreAnalyze();
	return r;
}



} // Snif::


