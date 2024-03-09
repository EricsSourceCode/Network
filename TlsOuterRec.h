// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "TlsMain.h"


// RFC 8446, Section 5.
// Record Protocol



class TlsOuterRec
  {
  private:
  bool testForCopy = false;
  CharBuf allBytes;
  Uint8 recordType = 0;
  Int32 recLength = 0;

  public:
  // The types of outer messages.
  static const Uint8 InvalidRec = 0;
  static const Uint8 ChangeCipherSpec = 20;
  static const Uint8 Alert = 21;
  static const Uint8 Handshake = 22;
  static const Uint8 ApplicationData = 23;
  static const Uint8 HeartBeat = 24; //  RFC 6520

  // Heartbeat as in the HeartBleed bug.  It was a
  // bug in OpenSSL.  No bounds check.
  // RFC 6520


  inline TlsOuterRec( void )
    {
    }

  inline TlsOuterRec( const TlsOuterRec& in )
    {
    if( in.testForCopy )
      return;

    throw "TlsOuterRec copy constructor called.";
    }

  inline ~TlsOuterRec( void )
    {
    }

  Uint32 accumByte( const Uint8 toAdd );

  static Int32 makeHandshakeRec(
                          const CharBuf& inBuf,
                          CharBuf& outBuf,
                          TlsMain& tlsMain );

  static Int32 makeAppDataRec(
                       const CharBuf& inBuf,
                       CharBuf& outBuf,
                       TlsMain& tlsMain );

  inline void clear( void )
    {
    allBytes.clear();
    }

  inline void copyBytes( CharBuf& copyTo ) const
    {
    // copyTo.clear();

    const Int32 last = allBytes.getLast();

    // Get the data that is after the outer
    // record header data.
    for( Int32 count = 5; count < last; count++ )
      {
      copyTo.appendU8( allBytes.getU8( count ));
      }
    }

  inline Uint8 getRecordType( void ) const
    {
    return recordType;
    }


  };
