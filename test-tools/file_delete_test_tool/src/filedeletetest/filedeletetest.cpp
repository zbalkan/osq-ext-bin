// ConsoleApplication11.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <string>

int __cdecl _tmain(int argc, TCHAR* argv[])
{
    std::cout << "Hello World!\n";

    HANDLE hFile = CreateFile(TEXT("c:\\test\\mytest.bat"),
        GENERIC_READ | GENERIC_WRITE | DELETE,
        0 /* exclusive access */,
        NULL,
        CREATE_ALWAYS,
        0,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        FILE_DISPOSITION_INFO fdi;
        fdi.DeleteFile = TRUE; // marking for deletion

        BOOL fResult = SetFileInformationByHandle(hFile,
            FileDispositionInfo,
            &fdi,
            sizeof(FILE_DISPOSITION_INFO));

        if (fResult)
        {
            // File will be deleted upon CloseHandle.
            _tprintf(TEXT("SetFileInformationByHandle marked c:\\test\\mytest.bat for deletion\n"));

            // ... 
            // Now use the file for whatever temp data storage you need,
            // it will automatically be deleted upon CloseHandle or 
            // application termination.
            // ...
        }
        else
        {
            _tprintf(TEXT("error %lu:  SetFileInformationByHandle could not mark c:\\test\\mytest.bat for deletion\n"),
                GetLastError());
        }

        Sleep(3000);

        CloseHandle(hFile);

        // At this point, the file is closed and deleted by the system.
        _tprintf(TEXT("At this point, the file is closed and deleted by the system.\n"));
    }
    else
    {
        _tprintf(TEXT("error %lu:  could not create c:\\test\\mytest.bat\n"),
            GetLastError());
    }
}

