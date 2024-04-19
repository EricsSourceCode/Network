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


// void HttpChunk::clear( void )
// {
// }



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

// The hex number can be any length, and
// it can have leading zeros.

// It can look like C000 or it can look
// like 0000C000 with those leading zeros.

// This count goes way past the end of it.
for( Int32 count = where; count < (where + 100);
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
      // Add extensions to this code.
      throw "Chunk has extensions.";
      // continue;
      }

    hexBuf.appendChar( oneChar );
    }
  }

// The hex size for dataLength doesn't
// include the CR LF at the end of the chunk.

// This can't read a chunk size bigger
// than 0x3FFFFFF.
// Which is something like a billion bytes.

dataLength = ByteHex::charBufToInt32( hexBuf );

return true;
}
