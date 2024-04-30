// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "TlsOuterRec.h"
#include "Alerts.h"
#include "Results.h"
#include "../CppBase/StIO.h"



Uint32 TlsOuterRec::accumByte( const Uint8 toAdd )
{
allBytes.appendU8( toAdd );
Int32 last = allBytes.getLast();

if( last == 1 )
  {
  // StIO::putLF();
  // StIO::putS( "\nNew Outer Rec." );
  // StIO::printF( "Byte is: " );
  // StIO::printFUD( toAdd );
  // StIO::putLF();

  if( toAdd == Handshake )
    {
    recordType = Handshake;
    // StIO::putS( "Outer Rec is handshake." );
    return Results::Continue; // Keep adding bytes.
    }

  if( toAdd == ChangeCipherSpec )
    {
    StIO::putS(
          "Outer Rec is ChangeCipherSpec." );

    recordType = ChangeCipherSpec;
    return Results::Continue;
    }

  if( toAdd == Alert )
    {
    StIO::putS( "Outer Rec is alert." );
    recordType = Alert;
    return Results::Continue;
    }

  if( toAdd == ApplicationData )
    {
    // StIO::putS(
    //      "Outer Rec is application data." );
    recordType = ApplicationData;
    return Results::Continue;
    }

  if( toAdd == HeartBeat )
    {
    StIO::putS( "Outer Rec is heartbeat." );
    recordType = HeartBeat;
    return Results::Continue;
    }

  // Unknown byte to deal with.
  throw "The outer record type is unknown.";
  // return Alerts::UnexpectedMessage;
  }

if( last == 5 )
  {
  // The bytes at positions 1 and 2 are legacy
  // version numbers, and they are ignored.

  recLength = allBytes.getU8( 3 );
  recLength <<= 8;
  recLength |= allBytes.getU8( 4 );

  if( recLength == 0 )
    {
    StIO::printF(
            "Outer Record length is zero." );
    return Alerts::DecodeError;
    }

  // Do more exact checks here.
  if( recLength >
               TlsMain::MaxRecordLengthCipher )
    {
    StIO::printF(
             "Outer Record length is too big." );
    return Alerts::RecordOverflow;
    }

  // StIO::printF( "Outer Record length: " );
  // StIO::printFD( recLength );
  // StIO::putLF();

  return Results::Continue;
  }

if( last > 5 )
  {
  if( last >= (recLength + 5) )
    {
    // StIO::putS(
    //  "Outer Rec is complete for length." );

    return Results::Done;
    }
  }

return Results::Continue;
}



Int32 TlsOuterRec::makeHandshakeRec(
                       const CharBuf& inBuf,
                       CharBuf& outBuf,
                       TlsMain& tlsMain )
{
outBuf.clear();
outBuf.appendU8( Handshake );

// The bytes at positions 1 and 2 are legacy
// version numbers, and they are ignored.
outBuf.appendU8( 3 );
outBuf.appendU8( 3 );

Int32 msgLength = inBuf.getLast();
Int32 maxLength = tlsMain.getMaxFragLength();

// This needs more work.
if( msgLength > maxLength )
  throw
   "TlsOuterRec Handshake msgLength > maxLength";

outBuf.appendU8( (msgLength >> 8) & 0xFF );
outBuf.appendU8( msgLength & 0xFF );

for( Int32 count = 0; count < msgLength; count++ )
  outBuf.appendU8( inBuf.getU8( count ));

// StIO::printF( "outBuf last: " );
// StIO::printFD( outBuf.getLast() );
// StIO::putLF();

// How many bytes of inBuf it sent.
return msgLength + 5;
}
