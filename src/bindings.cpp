// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
#include <windows.h>
#include <stdio.h>
#include <comutil.h>
#include <atlcomcli.h>
#include <netfw.h>

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

#define NET_FW_IP_PROTOCOL_TCP_NAME L"TCP"
#define NET_FW_IP_PROTOCOL_UDP_NAME L"UDP"

#define NET_FW_RULE_DIR_IN_NAME L"In"
#define NET_FW_RULE_DIR_OUT_NAME L"Out"

#define NET_FW_RULE_ACTION_BLOCK_NAME L"Block"
#define NET_FW_RULE_ACTION_ALLOW_NAME L"Allow"

#define NET_FW_RULE_ENABLE_IN_NAME L"TRUE"
#define NET_FW_RULE_DISABLE_IN_NAME L"FALSE"

struct fw_rule {
    char name[1024]="";
    char description[1024]="";
    char app_name[1024]="";
    char service_name[1024]="";
    long protocol=0;
    char icmp_type[1024]="";
    char local_ports[1024]="";
    char remote_ports[1024]="";
    char local_adresses[1024]="";
    char remote_addresses[1024]="";
    char profile1[1024]="";
    char profile2[1024]="";
    char profile3[1024]="";
    long direction=0;
    long action=0;
    char interface_types[1024]="";
    char interfaces[1024]="";
    long enabled=0;
    char grouping[1024]="";
    long edge_traversal=0;
};

fw_rule DumpFWRulesInCollection(INetFwRule* FwRule);
HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2);

void utf8_encode(const BSTR src, char* dst){
    WideCharToMultiByte(CP_UTF8, 0, (WCHAR*)((uint8_t*)src), SysStringLen(src), dst, 1024, NULL, NULL);
}

extern "C"
HRESULT getFWRules(fw_rule** rules, long* size, long* rules_count){
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    ULONG cFetched = 0; 
    CComVariant var;

    IUnknown *pEnumerator = NULL;
    IEnumVARIANT* pVariant = NULL;

    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;

    HRESULT res = S_OK;

    long fwRuleCount = 0;
    hrComInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED);

    if (hrComInit != RPC_E_CHANGED_MODE){
        if (FAILED(hrComInit)){
            wprintf(L"CoInitializeEx failed: 0x%08lx\n", hrComInit);
            res = S_FALSE;
            goto Cleanup;
        }
    }

    hr = WFCOMInitialize(&pNetFwPolicy2);
    if (FAILED(hr)){
        res = S_FALSE;
        goto Cleanup;
    }

    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)){
        wprintf(L"get_Rules failed: 0x%08lx\n", hr);
        res = S_FALSE;
        goto Cleanup;
    }

    hr = pFwRules->get_Count(&fwRuleCount);
    if (FAILED(hr)){
        wprintf(L"get_Count failed: 0x%08lx\n", hr);
        res = S_FALSE;
        goto Cleanup;
    }
    *rules_count = fwRuleCount;
    if (rules==NULL || *rules==NULL || fwRuleCount*sizeof(fw_rule) < *size){
        *size = fwRuleCount*sizeof(fw_rule);
        res = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;  
    }
    pFwRules->get__NewEnum(&pEnumerator);
    if(pEnumerator){
        hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void **) &pVariant);
    }

    int i=0;
    while(SUCCEEDED(hr) && hr != S_FALSE){
        hr = pVariant->Next(1, &var, &cFetched);
        if (S_FALSE != hr){
            if (SUCCEEDED(hr)){
                hr = var.ChangeType(VT_DISPATCH);
            }
            if (SUCCEEDED(hr)){
                hr = (V_DISPATCH(&var))->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&pFwRule));
            }
            if (SUCCEEDED(hr)){
                (*rules)[i] = DumpFWRulesInCollection(pFwRule);
                i++;
            }
            if(pFwRule != NULL){
                pFwRule->Release();
                pFwRule = NULL;
            }
            
            var.Clear();
        }
    }
    
Cleanup:
    if (pFwRule != NULL){
        pFwRule->Release();
    }
    if (pFwRules != NULL){
        pFwRules->Release();
    }
    if (pNetFwPolicy2 != NULL){
        pNetFwPolicy2->Release();
    }
    if (pVariant != NULL){
        pVariant->Release();
    }
    if (pEnumerator){
        pEnumerator->Release();
    }
    if (SUCCEEDED(hrComInit)){
        CoUninitialize();
    }
    return res;
}

void char_to_bstr(char* src, BSTR* bstr){
    int wslen = MultiByteToWideChar(CP_ACP, 0, src, strlen(src), 0, 0);
    if(wslen == 0){
        *bstr = NULL;
        return;
    }
    *bstr = SysAllocStringLen(0, wslen);
    MultiByteToWideChar(CP_ACP, 0, src, strlen(src), *bstr, wslen);
}

extern "C"
HRESULT newFWRule(fw_rule* rule){
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;

    long CurrentProfilesBitMask = 0;

    BSTR bstrRuleName;
    char_to_bstr(rule->name, &bstrRuleName);
    BSTR bstrRuleDescription;
    char_to_bstr(rule->description, &bstrRuleDescription);
    BSTR bstrRuleAppName;
    char_to_bstr(rule->app_name, &bstrRuleAppName);
    BSTR bstrRuleServiceName;
    char_to_bstr(rule->service_name, &bstrRuleServiceName);
    BSTR bstrRuleICMPType;
    char_to_bstr(rule->icmp_type, &bstrRuleICMPType);
    BSTR bstrRuleLocalPorts;
    char_to_bstr(rule->local_ports, &bstrRuleLocalPorts);
    BSTR bstrRuleRemotePorts;
    char_to_bstr(rule->remote_ports, &bstrRuleRemotePorts);
    BSTR bstrRuleLocalAdresses;
    char_to_bstr(rule->local_adresses, &bstrRuleLocalAdresses);
    BSTR bstrRuleRemoteAdresses;
    char_to_bstr(rule->remote_addresses, &bstrRuleRemoteAdresses);
    BSTR bstrRuleInterfaces;
    char_to_bstr(rule->interfaces, &bstrRuleInterfaces);
    BSTR bstrRuleInterfaceTypes;
    char_to_bstr(rule->interface_types, &bstrRuleInterfaceTypes);
    BSTR bstrRuleGrouping;
    char_to_bstr(rule->grouping, &bstrRuleGrouping);

    hrComInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (hrComInit != RPC_E_CHANGED_MODE){
        if (FAILED(hrComInit)){
            goto Cleanup;
        }
    }
    hr = WFCOMInitialize(&pNetFwPolicy2);
    if (FAILED(hr)){
        goto Cleanup;
    }
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)){
        goto Cleanup;
    }
    hr = pNetFwPolicy2->get_CurrentProfileTypes(&CurrentProfilesBitMask);
    if (FAILED(hr)){
        goto Cleanup;
    }
    if ((CurrentProfilesBitMask & NET_FW_PROFILE2_PUBLIC) && (CurrentProfilesBitMask != NET_FW_PROFILE2_PUBLIC)){
        CurrentProfilesBitMask ^= NET_FW_PROFILE2_PUBLIC;
    }
    hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pFwRule);
    if (FAILED(hr)){
        goto Cleanup;
    }
    pFwRule->put_Name(bstrRuleName);
    pFwRule->put_Description(bstrRuleDescription);
    pFwRule->put_ApplicationName(bstrRuleAppName);
    pFwRule->put_ServiceName(bstrRuleServiceName);
    pFwRule->put_Protocol(rule->protocol);
    pFwRule->put_IcmpTypesAndCodes(bstrRuleICMPType);
    pFwRule->put_LocalPorts(bstrRuleLocalPorts);
    pFwRule->put_RemotePorts(bstrRuleRemotePorts);
    pFwRule->put_LocalAddresses(bstrRuleLocalAdresses);
    pFwRule->put_RemoteAddresses(bstrRuleRemoteAdresses);
    pFwRule->put_Direction(NET_FW_RULE_DIRECTION(rule->direction));
    pFwRule->put_Action(NET_FW_ACTION(rule->action));
    pFwRule->put_InterfaceTypes(bstrRuleInterfaceTypes);
    pFwRule->put_Enabled(rule->enabled);
    pFwRule->put_Grouping(bstrRuleGrouping);
    pFwRule->put_Profiles(CurrentProfilesBitMask);
    pFwRule->put_EdgeTraversal(rule->edge_traversal);

    hr = pFwRules->Add(pFwRule);
    if (FAILED(hr)){
        goto Cleanup;
    }
Cleanup:
    SysFreeString(bstrRuleName);
    SysFreeString(bstrRuleDescription);
    SysFreeString(bstrRuleAppName);
    SysFreeString(bstrRuleServiceName);
    SysFreeString(bstrRuleICMPType);
    SysFreeString(bstrRuleLocalPorts);
    SysFreeString(bstrRuleRemotePorts);
    SysFreeString(bstrRuleLocalAdresses);
    SysFreeString(bstrRuleRemoteAdresses);
    SysFreeString(bstrRuleInterfaces);
    SysFreeString(bstrRuleInterfaceTypes);
    SysFreeString(bstrRuleGrouping);
    if (pFwRule != NULL){
        pFwRule->Release();
    }
    if (pFwRules != NULL){
        pFwRules->Release();
    }
    if (pNetFwPolicy2 != NULL){
        pNetFwPolicy2->Release();
    }
    if (SUCCEEDED(hrComInit)){
        CoUninitialize();
    }
    return hr;    
}

extern "C"
HRESULT delFWRule(char* rule_name){
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pFwRules = NULL;
    INetFwRule *pFwRule = NULL;

    long CurrentProfilesBitMask = 0;

    BSTR bstrRuleName;
    char_to_bstr(rule_name, &bstrRuleName);

    hrComInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (hrComInit != RPC_E_CHANGED_MODE){
        if (FAILED(hrComInit)){
            goto Cleanup;
        }
    }
    hr = WFCOMInitialize(&pNetFwPolicy2);
    if (FAILED(hr)){
        goto Cleanup;
    }
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)){
        goto Cleanup;
    }

    hr = pFwRules->Remove(bstrRuleName);
    if (FAILED(hr)){
        goto Cleanup;
    }
Cleanup:
    SysFreeString(bstrRuleName);
    if (pFwRules != NULL){
        pFwRules->Release();
    }
    if (pNetFwPolicy2 != NULL){
        pNetFwPolicy2->Release();
    }
    if (SUCCEEDED(hrComInit)){
        CoUninitialize();
    }
    return hr;    
}

fw_rule DumpFWRulesInCollection(INetFwRule* FwRule){
    fw_rule res;
    variant_t InterfaceArray;
    variant_t InterfaceString;  

    VARIANT_BOOL bEnabled;
    BSTR bstrVal;

    long lVal = 0;
    long lProfileBitmask = 0;

    NET_FW_RULE_DIRECTION fwDirection;
    NET_FW_ACTION fwAction;

    struct ProfileMapElement{
        NET_FW_PROFILE_TYPE2 Id;
        BSTR Name;
    };

    ProfileMapElement ProfileMap[3];
    ProfileMap[0].Id = NET_FW_PROFILE2_DOMAIN;
    ProfileMap[0].Name = L"Domain";
    ProfileMap[1].Id = NET_FW_PROFILE2_PRIVATE;
    ProfileMap[1].Name = L"Private";
    ProfileMap[2].Id = NET_FW_PROFILE2_PUBLIC;
    ProfileMap[2].Name = L"Public";

    if (SUCCEEDED(FwRule->get_Name(&bstrVal))){
        utf8_encode(bstrVal, res.name);
        SysFreeString(bstrVal);
    }
    if (SUCCEEDED(FwRule->get_Description(&bstrVal))){
        utf8_encode(bstrVal, res.description);
        SysFreeString(bstrVal);
    }
    if (SUCCEEDED(FwRule->get_ApplicationName(&bstrVal))){
        utf8_encode(bstrVal, res.app_name);
        SysFreeString(bstrVal);
    }
    if (SUCCEEDED(FwRule->get_ServiceName(&bstrVal))){
        utf8_encode(bstrVal, res.service_name);
        SysFreeString(bstrVal);
    }
    if (SUCCEEDED(FwRule->get_Protocol(&lVal))){
        res.protocol = lVal;
        if(lVal != NET_FW_IP_VERSION_V4 && lVal != NET_FW_IP_VERSION_V6){
            if (SUCCEEDED(FwRule->get_LocalPorts(&bstrVal))){
                utf8_encode(bstrVal, res.local_ports);
                SysFreeString(bstrVal);
            }
            if (SUCCEEDED(FwRule->get_RemotePorts(&bstrVal))){
                utf8_encode(bstrVal, res.remote_ports);
                SysFreeString(bstrVal);
            }
        }else{
            if (SUCCEEDED(FwRule->get_IcmpTypesAndCodes(&bstrVal))){
                utf8_encode(bstrVal, res.icmp_type);
                SysFreeString(bstrVal);
            }
        }
    }
    if (SUCCEEDED(FwRule->get_LocalAddresses(&bstrVal))){
        utf8_encode(bstrVal, res.local_adresses);
        SysFreeString(bstrVal);
    }
    if (SUCCEEDED(FwRule->get_RemoteAddresses(&bstrVal))){
        utf8_encode(bstrVal, res.remote_addresses);
        SysFreeString(bstrVal);
    }
    if (SUCCEEDED(FwRule->get_Profiles(&lProfileBitmask))){
        if ( lProfileBitmask & ProfileMap[0].Id){
            utf8_encode(ProfileMap[0].Name, res.profile1);
        }
        if ( lProfileBitmask & ProfileMap[1].Id){
            utf8_encode(ProfileMap[1].Name, res.profile2);
        }
        if ( lProfileBitmask & ProfileMap[2].Id){
            utf8_encode(ProfileMap[2].Name, res.profile3);
        }
    }
    if (SUCCEEDED(FwRule->get_Direction(&fwDirection))){
        res.direction = fwDirection;
    }
    if (SUCCEEDED(FwRule->get_Action(&fwAction))){
        res.action = fwAction;
    }
    if (SUCCEEDED(FwRule->get_Interfaces(&InterfaceArray))){
        if(InterfaceArray.vt != VT_EMPTY){
            SAFEARRAY    *pSa = NULL;
            pSa = InterfaceArray.parray;
            sprintf(res.interfaces, "");   
            for(long index= pSa->rgsabound->lLbound; index < (long)pSa->rgsabound->cElements; index++){
                SafeArrayGetElement(pSa, &index, &InterfaceString);
                sprintf(res.interfaces, "%s, %s", res.interfaces, (BSTR)InterfaceString.bstrVal);   
            }
        }
    }
    if (SUCCEEDED(FwRule->get_InterfaceTypes(&bstrVal))){
        utf8_encode(bstrVal, res.interface_types);
        SysFreeString(bstrVal);
    }
    if (SUCCEEDED(FwRule->get_Enabled(&bEnabled))){
        res.enabled = bEnabled;
    }
    if (SUCCEEDED(FwRule->get_Grouping(&bstrVal))){
        utf8_encode(bstrVal, res.grouping);
        SysFreeString(bstrVal);
    }
    if (SUCCEEDED(FwRule->get_EdgeTraversal(&bEnabled))){
        res.edge_traversal = bEnabled;
    }
    return res;
}

HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2){
    HRESULT hr = S_OK;
    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2), 
        NULL, 
        CLSCTX_INPROC_SERVER, 
        __uuidof(INetFwPolicy2), 
        (void**)ppNetFwPolicy2);
    if (FAILED(hr)){
        wprintf(L"CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
        goto Cleanup;        
    }

Cleanup:
    return hr;
}
