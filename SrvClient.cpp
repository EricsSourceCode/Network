// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "SrvClient.h"
#include "../CppBase/StIO.h"



SrvClient::SrvClient( void )
{
setTimeActiveNow();

StIO::putS( "SrvClient constructor called." );
}


SrvClient::SrvClient( SocketCpp useSocket )
{
mainSocket = useSocket;
StIO::putS( "SrvClient useSocket constructor." );
}



SrvClient::SrvClient( const SrvClient& in )
{
if( in.testForCopy )
  return;

const char* showS = "The SrvClient copy"
         " constructor should not get called.";

throw showS;
}



SrvClient::~SrvClient( void )
{
if( mainSocket != SocketsApi::InvalSock )
  {
  SocketsApi::closeSocket( mainSocket );
  mainSocket = SocketsApi::InvalSock;
  }

StIO::putS( "SrvClient destructor called." );
}



Int32 SrvClient::processData( void )
{
// This is meant to be virtual.  A derived
// class would have something to do here.

return 0;
}



void SrvClient::readSocket( CharBuf& recvBuf )
{
recvBuf.clear();

if( mainSocket == SocketsApi::InvalSock )
  return;

if( !allowRead )
  return;

if( !SocketsApi::receiveCharBuf(
                             mainSocket, recvBuf ))
  {
  // This socket will get closed.
  return;
  }

if( recvBuf.getLast() > 0 )
  setTimeActiveNow();

}



Int32 SrvClient::writeSocket(
                         const CharBuf& sendBuf )
{
if( mainSocket == SocketsApi::InvalSock )
  return 0;

const Int32 howMany = sendBuf.getLast();
if( howMany < 1 )
  return 0;

Int32 result = SocketsApi::sendCharBuf(
                     mainSocket, sendBuf );

if( result < howMany )
  {
  StIO::putS(
        "SrvClient could not send all data." );
  }

setTimeActiveNow();
return result;
}
