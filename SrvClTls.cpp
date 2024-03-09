// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "SrvClTls.h"
#include "../CppBase/StIO.h"



SrvClTls::SrvClTls( void )
{
setTimeActiveNow();

StIO::putS( "SrvClTls constructor called." );
}



SrvClTls::SrvClTls( SocketCpp useSocket )
                     // const CharBuf& address )
{
setTimeActiveNow();
mainSocket = useSocket;
// clientAddress.copy( address );
StIO::putS( "SrvClTls useSocket constructor." );
}



// This one is not virtual.
// SrvClTls::SrvClTls( const SrvClTls& in )



SrvClTls::~SrvClTls( void )
{
StIO::putS( "SrvClTls destructor called." );
}



Int32 SrvClTls::processData( void )
{
try
{
CharBuf recvBuf;
if( mainSocket != SocketsApi::InvalSock )
  readSocket( recvBuf );

Int32 recvLast = recvBuf.getLast();

// If it received nothing.
if( recvLast == 0 )
  {
  if( !isActive())
    {
    StIO::putS( "Closing inactive socket." );
    return -1; // Close it down now.
    }
  }

Int32 result = tlsMainSrv.processIncoming(
                          recvBuf, tlsMain );

if( result == 0 )
  setAllowReadFalse();
  // Let it time out and close.

if( result < 0 )
  return -1; // Shut it down now.

// What does tlsMainSrv want to send back?
CharBuf sendOutBuf;
tlsMainSrv.copyOutBuf( sendOutBuf );
Int32 outLast = sendOutBuf.getLast();
Int32 howMany = writeSocket( sendOutBuf );

if( howMany < outLast )
  {
  StIO::putS(
          "SrvClTls could not write all data." );
  // Then do what about this?
  // Use a CircleBuf to write it?
  }

return 1;

}
catch( const char* in )
  {
  StIO::putS(
        "Exception in SrvClTls.processData." );
  StIO::putS( in );
  return -1;
  }

catch( ... )
  {
  StIO::putS(
          "Exception in SrvClTls.processData" );
  return -1;
  }
}
