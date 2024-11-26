// segrun.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "excpt.h"
#include "helpers.h"

#include <dbghelp.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

typedef BOOL(WINAPI* VirtualProtect_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
    );

int main();

void ret()
{
    return;
}


DWORD_PTR searchRetGadget(void (*func)()) {
    unsigned char* ptr = (unsigned char*)func;
    size_t len = 128;

    for (size_t i = 0; i < len; ++i)
    {
        if (ptr[i] == 0xc3) return (DWORD_PTR)&ptr[i];
    }

    return NULL;
}


LONG WINAPI TopLevelExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    DWORD_PTR ret_address = searchRetGadget(ret);
    if (ret_address == NULL)
    {
        exit(1);
    }

    DWORD exceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;

    switch (exceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION:
        printf("Access Violation Exception\n");
        break;
    case EXCEPTION_BREAKPOINT:
        printf("Breakpoint Exception\n");
        break;
    case EXCEPTION_INVALID_HANDLE:
        printf( "Invalid Handle Exception\n");
        break;
    default:
        printf("Unknown Exception\n");
        break;
    }

    CONTEXT* context = pExceptionInfo->ContextRecord;
    //printf("Main: 0x%p\n", main);
    printf("Exception at: 0x%p\n", (void*)context->Rip);
    context->Rip = ret_address;
    SetThreadContext(GetCurrentThread(),context);
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
    printf("Segrun...\n");
    getchar();
    SetUnhandledExceptionFilter(TopLevelExceptionHandler);

    HMODULE hmodule = GetModuleHandleA("atcuf64.dll"); 
    printf("Module => %p\n", hmodule);
    DWORD textSize = NULL;
    HMODULE textAddress = NULL;
    if (hmodule != NULL)
    {
        
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hmodule;
        IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)hmodule + dosHeader->e_lfanew);

        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
            //printf("%s\n", sectionHeader[i].Name);
            if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
                textAddress = hmodule +sectionHeader[i].VirtualAddress;
                textSize = sectionHeader[i].SizeOfRawData;
                printf(".text => 0x%p, size => %d\n", textAddress,textSize);
                break;
            }
        }
        
    }
    else {
        printf("modulehandle error\n");
        return -1;
    }

    if (!textAddress) {
        printf("Error calculating .text section\n");
        return -1;
    }
    
    DWORD old;
    VirtualProtect_t pVirtualProtect = (VirtualProtect_t)hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), (char*)"VirtualProtect");
    BOOL rv = pVirtualProtect(textAddress, (unsigned int)textSize - 1024 * 246, PAGE_READONLY, &old);



    printf("SetWindowsHookEx: %p\n", SetWindowsHookEx);
    SetWindowsHookEx(NULL, NULL, NULL, NULL);

    printf("works!\n");
    MessageBoxA(NULL,NULL,0,0);

    return 0;
}