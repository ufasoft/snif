/*###########################################################################################################################
# Copyright (c) 1997-2012 Ufasoft   http://ufasoft.com   mailto:support@ufasoft.com                                         #
#                                                                                                                           #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License #
# as published by the Free Software Foundation; either version 3, or (at your option) any later version.                    #                                                          #
#                                                                                                                           #
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied        #
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.     #
#                                                                                                                           #
# You should have received a copy of the GNU General Public License along with this program;                                #
# If not, see <http://www.gnu.org/licenses/>                                                                                #
###########################################################################################################################*/

#include <el/ext.h>


#include "msgan.h"

namespace Snif {


class SearchAnalyzer : public CMessageAnalyzer, HttpSubscription {
	typedef map<String, DateTime> UriBaseMap;
	UriBaseMap m_uribase;

	void OnReceived(HttpDialog *dialog);
public:
	static SearchAnalyzer *I;

	SearchAnalyzer();

	~SearchAnalyzer() 	{
		I = 0;
	}
};

class CSearchMessageAnalyzerClass : public CMessageAnalyzerClass {
public:
	CSearchMessageAnalyzerClass()
		: CMessageAnalyzerClass("Search")
	{
	}

	CMessageAnalyzer *CreateObject() {
		return new SearchAnalyzer;
	}
} g_searchMessageAnalyzerClass;


SearchAnalyzer *SearchAnalyzer::I;

SearchAnalyzer::SearchAnalyzer()
	:	CMessageAnalyzer(nullptr)
{
	I = this;
}

static wregex s_reSearchHost("(?:.+\\.)?(google|yahoo|yandex|rambler|search\\.msn|baidu)\\.[a-z]+$", regex_constants::icase),	// prefix - 1
			s_reSearchQuery("^(/[a-z]+)?/([a-z]*s(ea)?(rch)?|results\\.aspx)\\?(.*)", regex_constants::icase);

void SearchAnalyzer::OnReceived(HttpDialog *dialog) {
	HttpDialog& d = *dialog;
	String shost = d.Request.Headers.Get("Host");
	if (!!shost) {
		if (regex_search(shost, s_reSearchHost)) {
			String uri = d.Request.RequestUri;
			if (regex_search(uri, s_reSearchQuery)) {
				NameValueCollection& params = d.Request.Params;
				String q = params.Get("q");
				if (q == "")
					q = params.Get("text");
				if (q == "")
					q = params.Get("p");
				if (q == "")
					q = params.Get("wd");
				if (q == "")
					q = params.Get("query");
				if (!!q) {
					q.Replace("+", " ");
					ptr<WebMessage> webm = new WebMessage();
					webm->m_analyzerClass = &g_searchMessageAnalyzerClass;
					webm->Text = q;
					webm->From = WebUser::GetByClientAddress(d.m_ci->SrcEndPoint.Address);
					webm->ClientAddress = d.m_ci->SrcEndPoint.Address;
					webm->Host = d.m_ci->DstEndPoint.Address.ToString();
					webm->Finish();
				}
			}
		}		
	}
}


} // Snif::
