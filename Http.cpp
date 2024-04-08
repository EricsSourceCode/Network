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




void Http::getWebPage( void )
{
StIO::putS( "Getting web page." );

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

  return;
  }

const char* getRequest = "GET / HTTP/1.1\r\n"
               "Host: www.durangoherald.com\r\n"
               "User-Agent: AINews\r\n"
               "Connection: keep-alive\r\n"
               "\r\n";

// Doesn't go in this request.
//            "Transfer-Encoding: chunked\r\n"

CharBuf appDataToSend;
appDataToSend.setFromCharPoint( getRequest );

// This will go out after the handshake.
httpOutBuf.addCharBuf( appDataToSend );

CharBuf fileBuf;
for( Int32 count = 0; count < 10000; count++ )
  {
  if( Signals::getControlCSignal())
    {
    StIO::putS( "Closing on Ctrl-C." );
    break;
    }

  StIO::putS(
      "\nTop of MainApp.processData loop()." );

  Int32 status = clientTls.processData(
                                  httpOutBuf,
                                  httpInBuf );

  if( status <= 0 )
    break;

  httpInBuf.appendToCharBuf( fileBuf, 10000 );

/*
Right after \r\n\r\n is the first chunk
length.

===== So how do you separate chunks?
Get it here:
https://en.wikipedia.org/wiki/Chunked_transfer_encoding

RFC 9112.
Each chunk is preceded by its size in bytes.
A zero length chunk means it's the end.
A zero length chunk doesn't have two or
four bytes.  Right?  Just the single
char 0 ?

The chunk size is in hexadecimal.
In Ascii.  Followed by optional params.
Ending with CrLf.
The chunk is terminated by CrLf.

CharBuf.setFromHexTo256( const CharBuf& hexBuf );



  // The data Transfer-Encoding should
  // be chunked, so there is no
  // Content-Length.
*/

  // If it got the full header.

// ===== Then it has to get the chunk length
// after that ending \r\n\r\n part.

// ===== The chunk data is at endHeader + 4
// plus what?

  Int32 endHeader = fileBuf.findText(
                             "\r\n\r\n", 0 );

  if( endHeader > 0 )
    {
    StIO::putS( "\nGot full header." );
    fileBuf.showAscii();
    return;
    }

  Threads::sleep( 50 );
  }

StIO::putS( "Finished getting web page." );
}
