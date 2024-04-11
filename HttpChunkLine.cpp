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


void HttpChunkLine::clear()
{
const Int32 last = arraySize;
for( Int32 count = 0; count < last; count++ )
  chunkArray[count].clear();

}



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
arrayLast = 1;

if( !chunkArray[0].getChunk( inBuf, where ))
  {
  arrayLast = 0;
  return false;
  }

return true;
}


/*
bool HttpChunkLine::getNextChunk(
                const CharBuf& inBuf,
                const Int32 where )
{


return true;
}
*/



#include "../CppMem/MemoryWarnBottom.h"
