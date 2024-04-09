// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// For information and guides see:
// https://ericssourcecode.github.io/



// RFC 9110 Section 6. Message Abstraction
// 6.4. Content

// RFC 9112:
// Section 7.1.
// Chunked Transfer Coding




#pragma once



#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"


class HttpChunk
  {
  private:
  bool testForCopy = false;

  public:
  HttpChunk( void )
    {
    }

  HttpChunk( const HttpChunk& in )
    {
    if( in.testForCopy )
      return;

    throw "HttpChunk copy constructor called.";
    }

  ~HttpChunk( void )
    {
    }

  };
