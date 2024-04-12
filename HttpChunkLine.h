// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// For information and guides see:
// https://ericssourcecode.github.io/




#pragma once



#include "HttpChunk.h"
#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppBase/Casting.h"


class HttpChunkLine
  {
  private:
  bool testForCopy = false;
  HttpChunk* chunkArray;
  Int32 arraySize = 2;
  Int32 arrayLast = 0;
  void resizeArrays( const Int32 toAdd );

  public:
  HttpChunkLine( void );
  HttpChunkLine( const HttpChunkLine& in );
  ~HttpChunkLine( void );

  void clear();
  bool hasFirstChunk( void )
    {
    if( arrayLast > 0 )
      return true;

    return false;
    }

  bool getFirstChunk( const CharBuf& inBuf,
                       const Int32 where );

  bool getNextChunk( const CharBuf& inBuf );
  bool hasAllChunks( void );

  };
