#define GMMODULE
#include "GarrysMod/Lua/Interface.h"
#include <stdio.h>
#include <string>
#include <Windows.h>
using namespace GarrysMod::Lua;
using namespace std;

#import "EvInterfaceSet.tlb" raw_interfaces_only

using namespace EvInterfaceSet;
#include <atlsafe.h>


extern "C"

#include "lua.h"


/*
ERSP Data Handler
Encrypted Relay Storage Protocol Data Handler
Packs and sends data to relays
*/

ITCPComPtr pTCPComClass;

int SendTCPMessage( lua_State* state )
{
	state->luabase->CheckType(1, GarrysMod::Lua::Type::STRING);
	const char* tmpchar = state->luabase->GetString(1);
	long tmplong = (long)state->luabase->GetNumber(2);
	const char* tmpchar2 = state->luabase->GetString(3);
	_bstr_t location(tmpchar);
	_bstr_t data(tmpchar2);
	BSTR pushdata;
	pTCPComClass->SendTCPMessage(location.GetBSTR(), tmplong, data.GetBSTR(), &pushdata);
	_bstr_t dreturn(pushdata);
	state->luabase->PushString(dreturn);
	return 1;
}

int Initialize(lua_State* state)
{
	const char* tmpKey = state->luabase->GetString(1);
	const char* tmpIV = state->luabase->GetString(2);
	_bstr_t tKey(tmpKey);
	_bstr_t tIV(tmpIV);
	pTCPComClass->Initialize(tKey.GetBSTR(), tIV.GetBSTR());
	return 0;
}

int EncryptStringToB64(lua_State* state)
{
	const char* tmpstring = state->luabase->GetString(1);
	BSTR tmppushdata;
	_bstr_t plaintext(tmpstring);
	pTCPComClass->EncryptStringToBase64(plaintext.GetBSTR(), &tmppushdata);
	_bstr_t pushdata(tmppushdata);
	state->luabase->PushString(pushdata);
	return 1;
}

int DecryptStringFromBase64(lua_State* state)
{
	const char* tmpstring = state->luabase->GetString(1);
	BSTR tmppushdata;
	_bstr_t b64text(tmpstring);
	pTCPComClass->DecryptStringFromBase64(b64text.GetBSTR(), &tmppushdata);
	_bstr_t pushdata(tmppushdata);
	state->luabase->PushString(pushdata);
	return 1;
}

GMOD_MODULE_OPEN()
{
	HRESULT hr = CoInitialize(NULL);
	pTCPComClass = *new ITCPComPtr(__uuidof(ManagedTCPComClass));

	LUA->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
		LUA->PushCFunction(SendTCPMessage);
		LUA->SetField(-2, "SendTCPMessage");
	LUA->Pop();

	LUA->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
		LUA->PushCFunction(Initialize);
		LUA->SetField(-2, "InitializeERSP");
	LUA->Pop();

	LUA->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
		LUA->PushCFunction(EncryptStringToB64);
		LUA->SetField(-2, "AESEncrypt");
	LUA->Pop();

	LUA->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
		LUA->PushCFunction(DecryptStringFromBase64);
		LUA->SetField(-2, "AESDecrypt");
	LUA->Pop();

	CoUninitialize();

	return 0;
}

GMOD_MODULE_CLOSE()
{
	return 0;
}