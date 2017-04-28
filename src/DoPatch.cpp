#include "Common.h"
#include "DllLoader.h"
#include "DoPatch.h"
#include "PatchUtil.h"
#include "minhook/include/MinHook.h"
#include "libudis86/udis86.h"
#include "utf8conv.h"
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi")
using namespace std;
using namespace utf8util;
uAddr uBase;

SOCKET h_socket(int af, int type, int protocol)
{
	return SOCKET_ERROR;
}

uint64_t cemu171customhash(DWORD HWID, DWORD timestamp, unsigned __int64* hash)
{
	return 0;
}

//#include "keys.c"
#include "sha256.h"

extern "C" int crackedbymudlord()
{
	return 1988;
}

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <windows.h>

// need link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

typedef hostent* (FAR  *REALHOST1)(const char* name);
REALHOST1 hostbyname = NULL;
hostent* __stdcall Mine_gethostbyname(const char* name)
{
	static struct in_addr  tmp_addr;
	tmp_addr.S_un.S_addr = 0x0100007f;
	static struct in_addr* tmp_addrlist[2] = { &tmp_addr, NULL };
	static struct hostent  tmp = { NULL, NULL, AF_INET, 4, (char**)tmp_addrlist };
	return &tmp;
	
}


typedef int(WINAPI *WSASTARTUP)(_In_  WORD      wVersionRequested,_Out_ LPWSADATA lpWSAData);
WSASTARTUP wininetcall = NULL;

int h_WSAStartup(
	WORD wVersionRequested, LPWSADATA lpWSAData
)
{
	WSADATA startupdata = { 0 };
	startupdata.wVersion = wVersionRequested;
	startupdata.wHighVersion = wVersionRequested;
	startupdata.iMaxSockets = 0;
	startupdata.iMaxUdpDg = 0;
	startupdata.lpVendorInfo = 0;
	strcpy(startupdata.szDescription, "WinSock 2.0");
	strcpy(startupdata.szSystemStatus, "Running");
	memcpy(lpWSAData, &startupdata, sizeof(WSADATA));
	return 0;
}

void DLL_patch(HMODULE base) {
	uBase = uAddr(base);
	PIMAGE_DOS_HEADER pDsHeader = PIMAGE_DOS_HEADER(uBase);
	PIMAGE_NT_HEADERS pPeHeader = PIMAGE_NT_HEADERS(uAddr(uBase) + pDsHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pPeHeader->OptionalHeader;
	SIZE_T size1 = pOptionalHeader->SizeOfCode;
	
	dprintf("Let's patch!\n");
	wchar_t szExePath[MAX_PATH];
	GetModuleFileName(nullptr, szExePath, MAX_PATH);
	dwprintf(L"szExePath: %s\n", szExePath);
//	if (0 != wcscmp(wcsrchr(szExePath, L'\\'), L"\\Cemu.exe")) {
		// Not my_target
		//dwprintf(L"Is not my target: %s\n", wcsrchr(szExePath, L'\\') + 1);
	//	return;
//	}
	uBase = uAddr(base);

	if (MH_Initialize() != MH_OK)
	{
		dprintf("Failed to initialize hooking library!\n");
		return;
	}

	if (MH_CreateHookApiEx(L"WSOCK32", "gethostbyname", &Mine_gethostbyname,NULL, NULL) != MH_OK)
	{
		dprintf("Failed to hook Internet functions!\n");
		return;
	}

	if (MH_CreateHookApiEx(L"WSOCK32", "WSAStartup", &h_WSAStartup, NULL, NULL) != MH_OK)
	{
		dprintf("Failed to hook Internet functions!\n");
	return;
	}

	if (MH_CreateHookApiEx(L"WSOCK32", "socket", &h_socket, NULL, NULL) != MH_OK)
	{
		dprintf("Failed to hook Internet functions!\n");
		return ;
	}
	//void* ptr = (uAddr*)(uBase + 0xEE200);
	

	size_t ptr1 = patternfind((unsigned char*)uBase, size1,"48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57");
	void* ptr = (uAddr*)(uBase + ptr1);
	if (MH_CreateHook(ptr, &cemu171customhash, NULL) != MH_OK)
	{
		dprintf("Failed to hook fingerprint functions!\n");
	}
	dprintf("Found fingerprint function at: %llx \n",uBase + ptr1);

	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
	{
		dprintf("Failed to hook Internet functions!\n");
		return;
	}

	patternsnr_mem((unsigned char*)uBase, size1, 
	"0F B7 54 24 ?? 44 8B 44 24 ??", //pattern to search
    "BA 43 59 00 00" //pattern to write
    );	
	FILE* fp_settings = NULL;
	fp_settings = fopen("serial.bin", "rb");
	if (fp_settings)
	{
		fclose(fp_settings);
		fp_settings = NULL;
		}
		else
		{
			unsigned char serial_data[60] = {
				0x74, 0x68, 0x69, 0x73, 0x63, 0x65, 0x6D, 0x75, 0x68, 0x61, 0x63, 0x6B,
				0x69, 0x73, 0x6D, 0x61, 0x64, 0x65, 0x62, 0x79, 0x6D, 0x75, 0x64, 0x6C,
				0x6F, 0x72, 0x64, 0x69, 0x6E, 0x32, 0x30, 0x31, 0x37, 0x2C, 0x6D, 0x61,
				0x79, 0x65, 0x78, 0x7A, 0x61, 0x70, 0x73, 0x75, 0x66, 0x66, 0x65, 0x72,
				0x66, 0x6F, 0x72, 0x68, 0x69, 0x73, 0x63, 0x72, 0x69, 0x6D, 0x65, 0x73
			};
			fp_settings = fopen("serial.bin", "wb");
			if (!fp_settings) return;
			int err = fwrite(serial_data, 60, 1, fp_settings);
			uint64_t size;
			if (!err)return;
			fclose(fp_settings);
			fp_settings = NULL;
		}
	
	dprintf("All done.\n==============================================\n");
}