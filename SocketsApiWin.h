// Copyright Eric Chauvin 2022 - 2023.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#pragma once


// A good tutorial:
// https://beej.us/guide/bgnet/html/


// The SocketCpp type is in BasicTypes.h

#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppMem/OpenCharArray.h"

// #include "../CppBase/RangeC.h"



class SocketsApi
  {
  private:
  bool testForCopy = false;

  public:
  static const SocketCpp InvalSock =
                      ~static_cast<Uint64>( 0 );


  SocketsApi( void );
  SocketsApi( const SocketsApi &in );
  ~SocketsApi( void );

  static void closeSocket( SocketCpp toClose );
  static void shutdownRead( SocketCpp toClose );

  static bool setNonBlocking(
                         const SocketCpp toSet );

  static SocketCpp connectClient(
                           const CharBuf& urlDomain,
                           const CharBuf& port );

  static SocketCpp openServer(
                      const char* ipAddress,
                      const char* port,
                      const bool useIPv4Only );

  static SocketCpp acceptConnect(
                          SocketCpp servSock,
                          CharBuf& fromAddress );

  static Int32 sendCharBuf(
                     const SocketCpp sendToSock,
                     const CharBuf& sendBuf );

  static bool receiveCharBuf(
                       const SocketCpp recSock,
                       CharBuf& recvBuf );

  };
