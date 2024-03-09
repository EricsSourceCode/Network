// Copyright Eric Chauvin 2022 - 2023.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/TimeApi.h"
#include "SocketsApi.h"



class NetClient
  {
  private:
  bool testForCopy = false;
  Int64 timeActive = 0;
  SocketCpp mainSocket = SocketsApi::InvalSock;

  public:
  NetClient( void );
  NetClient( const NetClient &in );
  ~NetClient( void );
  bool connect( const CharBuf& urlDomain,
                const CharBuf& port );
  Int32 sendCharBuf( const CharBuf& toSend );
  bool receiveCharBuf( CharBuf& toGet );

  void closeSocket( void );
  inline bool isConnected( void )
    {
    if( mainSocket == SocketsApi::InvalSock )
      return false;

    return true;
    }


  };
