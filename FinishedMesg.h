// Copyright Eric Chauvin 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// See https://ericinarizona.github.io/
// For guides and information.


#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppInt/IntegerMath.h"
// #include "DerEncode.h"
#include "Alerts.h"
#include "Results.h"
#include "TlsMain.h"


// RFC 8446 section-4.4.4 Finished



class FinishedMesg
  {
  private:
  bool testForCopy = false;

  public:
  FinishedMesg( void )
    {
    }

  FinishedMesg( const FinishedMesg& in )
    {
    if( in.testForCopy )
      return;

    throw "FinishedMesg copy constructor.";
    }

  ~FinishedMesg( void )
    {
    }

  Uint32 parseMsg(
                  const CharBuf& finishBuf,
                  TlsMain& tlsMain );

  };
