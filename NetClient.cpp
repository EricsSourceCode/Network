// Copyright Eric Chauvin 2022 - 2023.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "NetClient.h"
#include "../CppBase/Casting.h"
#include "../CppBase/TimeApi.h"
#include "../CppBase/StIO.h"



NetClient::NetClient( void )
{
}



NetClient::NetClient( const NetClient &in )
{
if( in.testForCopy )
  return;

const char* showS = "The NetClient copy constructor"
         " should not be getting called.";

throw showS;
}



NetClient::~NetClient( void )
{
closeSocket();
}



bool NetClient::connect( const CharBuf& urlDomain,
                         const CharBuf& port )
{
mainSocket = SocketsApi::connectClient(
                    urlDomain, port );

if( mainSocket == SocketsApi::InvalSock )
  return false;

timeActive = TimeApi::getSecondsNow();
return true;
}


Int32 NetClient::sendCharBuf(
                         const CharBuf& toSend )
{
if( mainSocket == SocketsApi::InvalSock )
  return 0;

return SocketsApi::sendCharBuf( mainSocket, toSend );
}


bool NetClient::receiveCharBuf( CharBuf& toGet )
{
if( mainSocket == SocketsApi::InvalSock )
  return false;

if( !SocketsApi::receiveCharBuf( mainSocket, toGet ))
  {
  StIO::putS( "receiveCharBuf returned false." );

  closeSocket();
  return false;
  }

// The toGet CharBuf might have zero characters
// in it.  That just means there was no data
// to receive yet.

return true;
}




void NetClient::closeSocket( void )
{
if( mainSocket == SocketsApi::InvalSock )
  return;

SocketsApi::closeSocket( mainSocket );
mainSocket = SocketsApi::InvalSock;
}
