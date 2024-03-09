// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "ServerTls.h"
#include "../CppBase/StIO.h"
#include "../CppBase/Threads.h"
#include "../Network/SrvClTls.h"



ServerTls::ServerTls( void )
{
}



ServerTls::ServerTls( const ServerTls& in )
{
if( in.testForCopy )
  return;

const char* showS = "The ServerTls copy"
         " constructor should not get called.";

throw showS;
}



ServerTls::~ServerTls( void )
{
}



bool ServerTls::startServer( const char* address,
                             const char* port )
{
return server.startServer( address, port );
}


void ServerTls::mainLoop( void )
{
CharBuf fromCBuf;

while( true )
  {
  // StartLoopTime = something

  StIO::putS( "Top of mainLoop()." );

  if( !server.oneLoop() )
    return;

  // accept() until there are no more sockets
  // to accept.
  for( Int32 count = 0; count < 100; count++ )
    {
    fromCBuf.clear();
    SocketCpp acceptedSock =
                 SocketsApi::acceptConnect(
                          server.getMainSocket(),
                          fromCBuf );

    // No more sockets to accept.
    if( acceptedSock == SocketsApi::InvalSock )
      break;

    // Add the kind of SrvClient socket I
    // want to add.

    server.addNewClient( new SrvClTls(
                                 acceptedSock ));

    StIO::putS( "Added new SrvClTls:" );
    StIO::putCharBuf( fromCBuf );
    StIO::putS( " " );
    }

  // FinishLoopTime = something
  // Do this dynamically and adjust it to sleep
  // more or less or none if it's busy.
  Int32 milliSec = 1000;
  Threads::sleep( milliSec );
  }
}
