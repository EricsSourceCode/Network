// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#pragma once


#include "../CppBase/BasicTypes.h"
// #include "../CppBase/CharBuf.h"
#include "Server.h"




class ServerTls
  {
  private:
  bool testForCopy = false;
  Server server;

  public:
  ServerTls( void );
  ServerTls( const ServerTls &in );
  ~ServerTls( void );
  bool startServer( const char* address,
                    const char* port );
  void mainLoop( void );

  };
