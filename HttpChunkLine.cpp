// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



// For information and guides see:
// https://ericssourcecode.github.io/


#include "HttpChunkLine.h"
#include "../CppBase/StIO.h"



HttpChunkLine::HttpChunkLine( void )
{
chunkArray = new HttpChunk[
             Casting::i32ToU64( arraySize )];

}


HttpChunkLine::HttpChunkLine(
                      const HttpChunkLine& in )
{
if( in.testForCopy )
  return;

chunkArray = new HttpChunk[
             Casting::i32ToU64( arraySize )];

throw "HttpChunkLine copy constructor.";
}


HttpChunkLine::~HttpChunkLine( void )
{
delete[] chunkArray;
}



#include "../CppMem/MemoryWarnTop.h"


/*
void HttpChunkLine::clear()
{
const Int32 last = arraySize;
for( Int32 count = 0; count < last; count++ )
  chunkArray[count].clear();

}
*/


void HttpChunkLine::resizeArrays(
                           const Int32 toAdd )
{
if( arrayLast > arraySize )
  throw
     "HttpChunkLine::resizeArrays arrayLast";

const Int32 newSize = arraySize + toAdd;

HttpChunk* newChunkArray;
newChunkArray = new HttpChunk[
             Casting::i32ToU64( newSize )];

const Int32 max = arrayLast;
for( Int32 count = 0; count < max; count++ )
  newChunkArray[count].copy( chunkArray[count] );

arraySize = newSize;
delete[] chunkArray;
chunkArray = newChunkArray;
}



bool HttpChunkLine::getFirstChunk(
                const CharBuf& inBuf,
                const Int32 where )
{
if( !chunkArray[0].getChunk( inBuf, where ))
  {
  arrayLast = 0;
  return false;
  }

// StIO::putS( "After got first chunk." );
// Int32 begin = chunkArray[0].getBeginData();
// StIO::printF( "begin first: " );
// StIO::printFD( begin );
// StIO::putLF();

arrayLast = 1;
return true;
}




bool HttpChunkLine::getNextChunk(
                        const CharBuf& inBuf )
{
// StIO::putS( "\nTop of getNextChunk." );

if( arrayLast < 1 )
  throw "arrayLast < 1 in getNextChunk.";

if( hasAllChunks())
  return true;

// How many chunks in a big file?
if( (arrayLast + 2) >= arraySize )
  resizeArrays( 1024 * 2 );

const Int32 where = arrayLast - 1;

Int32 begin = chunkArray[where].getBeginData();
Int32 length = chunkArray[where].getDataLength();

// The hex size for dataLength doesn't
// include the CR LF at the end of the chunk.

const Int32 nextStart = begin + length + 2;

// Getting a billion byte file with this?
if( nextStart > 1000000000 )
  throw "HttpChunkLine nextStart too big.";

const Int32 inBufLast = inBuf.getLast();

// Chunks can be much longer that the Outer
// Record length, which is usually
// 16K, or 0x4000.

if( (nextStart + 3) >= inBufLast )
  {
  // Not enough data for the next chunk.
  return true;
  }

if( chunkArray[where + 1].getChunk( inBuf,
                                 nextStart ))
  {
  arrayLast++;
  }

return true;
}



bool HttpChunkLine::hasAllChunks( void )
{
if( arrayLast < 1 )
  return false;

const Int32 where = arrayLast - 1;

Int32 length = chunkArray[where].getDataLength();
if( length == 0 )
  return true;

return false;
}



void HttpChunkLine::assembleChunks(
                       CharBuf& toGet,
                       const CharBuf& inBuf )
{
toGet.clear();

const Int32 max = arrayLast;
for( Int32 count = 0; count < max; count++ )
  {
  Int32 begin = chunkArray[count].getBeginData();
  Int32 length = chunkArray[count].
                            getDataLength();
  if( length == 0 )
    {
    // But what about the Trailer?
    break;
    }

  Int32 where = begin;
  for( Int32 bytes = 0; bytes < length; bytes++ )
    {
    toGet.appendU8( inBuf.getU8( where ));
    where++;
    }
  }
}




#include "../CppMem/MemoryWarnBottom.h"
