// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



// For information and guides see:
// https://ericssourcecode.github.io/


#include "Http.h"
#include "../CppBase/StIO.h"
#include "../WinApi/Signals.h"
#include "ClientTls.h"
#include "../CppBase/Threads.h"


// Look for: </html>
// Make sure it's all there.


// https://en.wikipedia.org/wiki/
//               List_of_HTTP_header_fields


// HTTP/1.1
// RFC 2818, 9110, 9112.




bool Http::getWebPage( void )
{
StIO::putS( "Getting web page." );

httpChunkLine.clear();

ClientTls clientTls;


// Add other news sites like Leadville,
// The Economist, etc.

// "https://www.msnbc.com/"
// "https://www.foxnews.com/"

// if( !clientTls.startHandshake( "127.0.0.1",
//                               "443" ))

// if( !clientTls.startTestVecHandshake(
//                             "127.0.0.1",
//                             "443" ))


if( !clientTls.startHandshake(
                        "durangoherald.com",
                        "443" ))
  {
  StIO::putS(
        "ClientTls false on startHandshake." );

  return false;
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

const char* getRequest = "GET / HTTP/1.1\r\n"
               "Host: www.durangoherald.com\r\n"
               "User-Agent: AINews\r\n"
               "Connection: keep-alive\r\n"
               "TE: trailers\r\n"
               "\r\n";

CharBuf appDataToSend;
appDataToSend.setFromCharPoint( getRequest );

// This will go out after the handshake.
httpOutBuf.addCharBuf( appDataToSend );

Int32 endHeader = -1;
CharBuf header;
CharBuf getHttpBuf;
for( Int32 count = 0; count < 10000; count++ )
  {
  if( Signals::getControlCSignal())
    {
    StIO::putS( "Closing on Ctrl-C." );
    return false;
    }

  StIO::putS(
        "\nTop of Http::getWebPage() loop." );

  Int32 status = clientTls.processData(
                                  httpOutBuf,
                                  httpInBuf );

  if( status <= 0 )
    break;

  httpInBuf.appendToCharBuf( getHttpBuf, 10000 );

  // Right after \r\n\r\n at the end of
  // the header is the first chunk
  // length.  Like \r\n\r\n2000\r\n

  if( endHeader < 0 )
    {
    endHeader = getHttpBuf.findText(
                             "\r\n\r\n", 0 );

    if( endHeader > 0 )
      {
      StIO::putS( "\nGot full header." );
      header.copy( getHttpBuf );
      header.showAscii();
      StIO::putLF();
      // Make sure the header says it is
      // chunked:
      // Transfer-Encoding: chunked.
      }
    }

  if( endHeader > 0 )
    {
    if( !httpChunkLine.hasFirstChunk())
      {
      httpChunkLine.getFirstChunk(
                              getHttpBuf,
                              endHeader + 4 );

      // ===========
      // Break it off here for now.
      return true;
      }
    else
      {
      // =======
      // Get next chunk.
      }
    }

  Threads::sleep( 50 );
  }

StIO::putS( "Finished getting web page." );
return true;
}
