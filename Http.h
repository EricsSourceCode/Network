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
#include "../CppBase/CircleBuf.h"
#include "HttpChunkLine.h"
#include "ClientTls.h"



class Http
  {
  private:
  bool testForCopy = false;
  CircleBuf httpOutBuf;
  CircleBuf httpInBuf;
  HttpChunkLine httpChunkLine;
  CharBuf getHttpBuf;
  ClientTls clientTls;

  public:
  Http( void )
    {
    httpOutBuf.setSize( 1024 * 64 );
    httpInBuf.setSize( 1024 * 1024 * 64 );
    }

  Http( const Http& in )
    {
    if( in.testForCopy )
      return;

    throw "Http copy constructor called.";
    }

  ~Http( void )
    {
    }

  bool getWebPage( const CharBuf& fileName );
  bool getAllChunks( const CharBuf& fileName );

  };
