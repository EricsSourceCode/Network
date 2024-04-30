// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



// For information and guides see:
// https://ericssourcecode.github.io/


#include "Http.h"
#include "../CppBase/StIO.h"
#include "../CppBase/FileIO.h"
#include "../WinApi/Signals.h"
#include "../CppBase/Threads.h"



// HTTP/1.1
// RFC 2818, 9110, 9112.




bool Http::getWebPage( const CharBuf& domain,
                       const CharBuf& serverName,
                       const CharBuf& fileName )
{
StIO::putS( "Getting web page." );
serverName.showAscii();
StIO::putS( "\n\n" );

// httpChunkLine.clear();

if( serverName.contains( "loopback" ))
  {
  if( !clientTls.startTestVecHandshake(
                        "127.0.0.1", "443" ))
/*
  if( !clientTls.startHandshake( "127.0.0.1",
                                     "443" ))
*/
    {
    StIO::putS(
        "ClientTls false on startHandshake." );

    return false;
    }
*/
  }
else
  {
  if( !clientTls.startHandshake(
                               domain,
                               "443" ))
    {
    StIO::putS(
        "ClientTls false on startHandshake." );

    return false;
    }
  }

// TE is what Transfer Encodings you will
// accept.
// Like:
// TE: deflate
// Transfer-Encoding is the response header.
// Don't specify chunked with TE
// because it is always acceptable.
// TE: trailers
// means you are willing to accept trailers.

// "www." + domain

CharBuf appDataToSend;

const char* getRequest = "GET / HTTP/1.1\r\n"
                         "Host: ";

appDataToSend.appendCharPt( getRequest );

appDataToSend.appendCharBuf( serverName );

const char* getRequest2 = "\r\n"
               "User-Agent: AINews\r\n"
               "Connection: keep-alive\r\n"
               "TE: trailers\r\n"
               "\r\n";

appDataToSend.appendCharPt( getRequest2 );

StIO::putS( "Get Request:" );
appDataToSend.showAscii();
StIO::putS( "\n\n" );

// This will go out after the handshake.
httpOutBuf.addCharBuf( appDataToSend );

Int32 endHeader = -1;
CharBuf header;
getHttpBuf.clear();
for( Int32 count = 0; count < 10000; count++ )
  {
  if( Signals::getControlCSignal())
    {
    StIO::putS( "Closing on Ctrl-C." );
    return false;
    }

  // StIO::putS( "Http::getWebPage() loop." );

  Int32 status = clientTls.processData(
                                  httpOutBuf,
                                  httpInBuf );

  if( status <= 0 )
    {
    StIO::putS( "ClientTls returned <= 0" );
    return false;
    }

  httpInBuf.appendToCharBuf( getHttpBuf, 10000 );

  // Right after \r\n\r\n at the end of
  // the header is the first chunk
  // length.  Like \r\n\r\n2000\r\n

  if( endHeader < 0 )
    {
    endHeader = getHttpBuf.findText(
                             "\r\n\r\n", 0 );

    // If it just found it for the first time.
    if( endHeader > 0 )
      {
      // Make sure the header says it is
      // chunked:
      // Transfer-Encoding: chunked.

      StIO::putS( "\n\nGot full header." );

      header.copy( getHttpBuf );

      StIO::putS( "Header:" );
      header.showAscii();
      StIO::putS( "\n\n" );

      // parseHeader()
      }
    }

  if( endHeader > 0 )
    {
    if( httpChunkLine.hasFirstChunk())
      break;

    httpChunkLine.getFirstChunk( getHttpBuf,
                              endHeader + 4 );
    }

  Threads::sleep( 50 );
  }

return getAllChunks( fileName );
}



bool Http::getAllChunks( const CharBuf& fileName )
{
StIO::putS( "Getting all chunks." );

for( Int32 count = 0; count < 100000; count++ )
  {
  if( Signals::getControlCSignal())
    {
    StIO::putS( "Closing on Ctrl-C." );
    return false;
    }

  // StIO::putS( "getAllChunks loop." );

  Int32 status = clientTls.processData(
                                  httpOutBuf,
                                  httpInBuf );

  if( status <= 0 )
    {
    StIO::putS( "ClientTls returned <= 0" );
    return false;
    }

  httpInBuf.appendToCharBuf( getHttpBuf, 100000 );

  if( !httpChunkLine.getNextChunk( getHttpBuf ))
    return false;

  if( httpChunkLine.hasAllChunks())
    {
    // StIO::putS( "It has all chunks.\n\n" );

    CharBuf fileBuf;
    httpChunkLine.assembleChunks( fileBuf,
                                  getHttpBuf );
    // StIO::putS( "\n\n\nWhole File:\n" );
    // fileBuf.showAscii();
    // StIO::putS( "\n\n\nEnd of file.\n" );

    FileIO::writeAll( fileName,
                  fileBuf );

    // But what about the Trailer?
    return true;
    }

  Threads::sleep( 15 );
  }

StIO::putS( "It should never get here." );
return true;
}
