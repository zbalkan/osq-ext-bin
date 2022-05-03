#include <iostream>
#include <windows.h>
#include <tchar.h>

int __cdecl _tmain(int argc, TCHAR* argv[])
{
    std::cout << "Hello World!\n";

    if ((argc == 1) || (argc == 2 && (_wcsicmp(argv[1], _T("-delbydisp")) == 0)))
    {
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
            _tprintf(TEXT("error %lu: could not create c:\\test\\mytest.bat\n"),
                GetLastError());
        }
    }
    else if (argc == 2 && (_wcsicmp(argv[1], _T("-del")) == 0))
    {
        system("echo hi > c:\\test\\mytest2.bat");

        Sleep(3000);

        system("del c:\\test\\mytest2.bat");

        // At this point, the file is closed and deleted by the system.
        _tprintf(TEXT("At this point, the file c:\\test\\mytest2.bat is deleted by the system via del command.\n"));
    }
}

