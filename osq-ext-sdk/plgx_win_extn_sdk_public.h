/****************************************************************************
 * Copyright (C) 2018 by PolyLogyx, LLC                                     *
 *                                                                          *
 *  This source code is licensed under  the Apache 2.0 license (found in    *
 *  the LICENSE file in the root directory of this source tree)             *
 *                                                                          *
 ****************************************************************************/

#ifndef __PLGX_CLIENT_PUBLIC_H__
#define __PLGX_CLIENT_PUBLIC_H__

/*
 * A callback function that gets invoked in response to the query execution request
 */
typedef void (*fnCallback)(void *, DWORD, char*);


/*
 * The function signature that the DLL provides as a proxy function to send queries
 * to osquery
 */
typedef DWORD (*fpPlgxExecuteQuery)(char *, fnCallback);


typedef std::vector< std::map <std::string, std:: string> > QueryResultType; 

#endif
