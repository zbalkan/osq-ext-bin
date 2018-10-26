/****************************************************************************
* Copyright (C) 2018 by PolyLogyx, LLC                                     *
*                                                                          *
*  This source code is licensed under  the Apache 2.0 license (found in    *
*  the LICENSE file in the root directory of this source tree)             *
*                                                                          *
****************************************************************************/

#include "stdio.h"
#include "windows.h"
#include "iostream"
#include "vector"
#include "map"
#include "plgx_win_extn_sdk_public.h"

using namespace std;

bool bQueryResultsPrinted = false;

void Callback(void* Result, DWORD ErrorCode, char* ErrorString)
{
    if (ErrorCode != ERROR_SUCCESS)
    {
        if (ErrorString)
            printf("%s\n", ErrorString);

        return;
    }

    QueryResultType QueryResult(*(QueryResultType *)Result);

    for (const auto& each : QueryResult) 
    {
        for (const auto& it : each) 
        {
            cout << it.first.c_str() << ": " << it.second.c_str();
            cout << "\n";
        }
    }

    printf("All done\n");
    bQueryResultsPrinted = true;
}

void
ShowHelp(char* ProgramName)
{
    printf("\n");
    printf("This is a test program to demonstrate sending SQL queries to osqueryd.\n\n");
    printf("This is not meant to be a replacement for osqueryi shell but gives an alternate\n");
    printf("option to get osquery data. This can allow any local endpoint application to communicate\n");
    printf("without having to be an osquery extension itself.\n");
    printf("Additionally the SDK allows for being able to write scripts or program (e.g. UI) around osquery which is not possible\n");
    printf("with the osquery shell \n");
    
    printf("\n");
    
    printf("For this program and SDK to work, YOU MUST be running osquery with PolyLogyx Extension\n");
    printf("For more on PolyLogyx Extension: https://github.com/polylogyx/osq-ext-bin \n\n");
    

    printf("Use the following syntax to send queries to osquery daemon \n");
    printf("\n");
    printf("%s \"<sql-query>;\" \n\n", ProgramName);
    printf("where <sql-query> is the query string as it would have been if running via osqueryi shell\n");
    printf("\n");
    printf("Example usage: %s \"select * from time;\"\n\n", ProgramName);
    printf("Non-query shell commands like .tables or .schema etc are not supported.\n");
    printf("The query results are printed with each key-value per line. \n");
    printf("\n");
    printf("The program comes with no guarantees or warranties. Use at your discretion.\n");
    printf("For any feedback, suggestion or issues, mail at open@polylogyx.com\n");
    printf("\n");
}

int main(int argc, char** argv)
{
    HMODULE h_dll;
    fpPlgxExecuteQuery func = NULL;

    if (argc < 2)
    {
        ShowHelp(argv[0]);
        return 0;
    }

   /*
    * Load the DLL. It is assumed the dll is present in the local folder or in the path
    */
    h_dll = LoadLibrary(L"plgx-win-extn-client-sdk.dll");  

    if (h_dll)
    {
       /*
        * Find the function address needed from DLL to send the queries to
        */
        func = (fpPlgxExecuteQuery)GetProcAddress(h_dll, "PlgxExecuteQuery");
        if (func)
        {
#if _DEBUG
            printf("PlgxExecuteQuery Found\n");
#endif
        }
        else
        {
            printf("Error is %d\n", GetLastError());
            return 0;
        }
    }
    else
    {
        printf("Unable to load plgx-win-extn-client.dll");
    }


    func(argv[1], Callback);

    /* A lazy way of waiting till all the callback gets invoked and query resutls are printed */
    while(bQueryResultsPrinted == false)
        Sleep(10);

    return 0;
}

