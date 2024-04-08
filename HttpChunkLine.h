// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// For information and guides see:
// https://ericssourcecode.github.io/




#pragma once



#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"


class HttpChunkLine
  {
  private:
  bool testForCopy = false;

  public:
  HttpChunkLine( void )
    {
    }

  HttpChunkLine( const HttpChunkLine& in )
    {
    if( in.testForCopy )
      return;

    throw "HttpChunkLine copy constructor.";
    }

  ~HttpChunkLine( void )
    {
    }

  };


