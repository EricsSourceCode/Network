// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



// For information and guides see:
// https://ericssourcecode.github.io/


#include "HttpChunk.h"
#include "../CppBase/StIO.h"
#include "../CppBase/ByteHex.h"


void HttpChunk::clear( void )
{

}



void HttpChunk::copy( const HttpChunk& in )
{
beginHexTag = in.beginHexTag;
beginData = in.beginData;
dataLength = in.dataLength;
}



bool HttpChunk::getChunk( const CharBuf& inBuf,
                          const Int32 where )
{
if( !inBuf.findText( "\r\n", where ))
  return false;

const Int32 inBufLast = inBuf.getLast();

beginHexTag = where;

bool gotExtension = false;
CharBuf hexBuf;

// The hex number can be any length, so make it
// no longer than 6 hex chars.
// 6 digits at base 16.

for( Int32 count = where; count < (where + 6);
                                       count++ )
  {
  if( count >= inBufLast )
    return false;

  char oneChar = inBuf.getC( count );
  if( oneChar == '\r' )
    {
    beginData = count + 2;
    break;
    }

  if( !gotExtension )
    {
    if( oneChar == ';' )
      {
      // If there are extensions after the
      // hexidecimal numbers it is delimited
      // by a semicolon.

      gotExtension = true;
      StIO::putS( "Chunk has extensions." );
      continue;
      }

    hexBuf.appendChar( oneChar );
    }
  }

// The hex size for dataLength doesn't
// include the CR LF at the end of the chunk.

dataLength = ByteHex::charBufToInt32( hexBuf );

StIO::printF( "dataLength: " );
StIO::printFD( dataLength );
StIO::putLF();

return true;
}
