// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




#include "CertMesg.h"
#include "Alerts.h"
#include "Results.h"
#include "Certificate.h"
#include "ExtenList.h"
#include "../CppBase/StIO.h"



Uint32 CertMesg::parseCertMsg(
                    const CharBuf& certBuf,
                    TlsMain& tlsMain )
{
StIO::putS( "Parsing Certificate Message." );

// StIO::putLF();
// certBuf.showHex();
// StIO::putLF();

// The certificate message is in RFC 8446
// section-4.4.2.

// Certificate type:
//        X509(0),
//        RawPublicKey(2),


const Int32 last = certBuf.getLast();
StIO::printF( "certBuf last: " );
StIO::printFD( last );
StIO::putLF();

if( last < 4 )
  {
  throw "parseCertMsg: certBuf last < 4.";
  // return Results:: something.
  }

Uint8 certType = certBuf.getU8( 0 );

// RFC 7250 Raw Public Keys

// Can't deal with Raw Public Key yet.
if( certType != 0 )
  throw "Certificate type is not X509.";

// "in the case of server authentication,
// this field SHALL be zero length."

// This is not there if the server is sending
// this message.
// Uint8 certRequestContext = certBuf.getU8( 1 );

Uint32 certListLength = certBuf.getU8( 1 );
certListLength <<= 8;
certListLength |= certBuf.getU8( 2 );
certListLength <<= 8;
certListLength |= certBuf.getU8( 3 );

StIO::printF( "certListLength: " );
StIO::printFUD( certListLength );
StIO::putLF();

Int32 index = 4;

if( (index + 3) >= last )
  {
  throw "Nothing left in certBuf.";
  // return Results::  something;
  }

for( Int32 certCount = 0; certCount < 100;
                            certCount++ )
  {
  Uint32 certLength = certBuf.getU8( index );
  index++;
  certLength <<= 8;
  certLength |= certBuf.getU8( index );
  index++;
  certLength <<= 8;
  certLength |= certBuf.getU8( index );
  index++;

  // if( certLength == 0 )
  // Or if it is too big...

  StIO::printF( "certLength: " );
  StIO::printFUD( certLength );
  StIO::putLF();

  CharBuf oneCertBuf;

  for( Uint32 count = 0; count < certLength;
                                count++ )
    {
    oneCertBuf.appendU8(
                    certBuf.getU8( index ));
    index++;
    }

  Certificate cert;

  // if result is an alert...

  Uint32 result = cert.parseOneCert(
                            oneCertBuf,
                            tlsMain );

  if( result != Results::Done )
    {
    throw "cert.parseOneCert was bad.";
    // return result;
    }

  if( (index + 3) >= last )
    {
    StIO::putS( "Nothing left in certBuf." );
    return Results::Done;
    }


  // The extensions that come after a
  // certificate.
  // Two bytes for the length.
  Uint32 extenLength = certBuf.getU8( index );
  index++;
  extenLength <<= 8;
  extenLength |= certBuf.getU8( index );
  index++;
  StIO::printF( "extenLength: " );
  StIO::printFUD( extenLength );
  StIO::putLF();

  // Do something with these extensions.
  if( extenLength != 0 )
    throw "CertMesg extenLength != 0";

  }

StIO::putS( "\nEnd of CertMessage.\n\n" );

return Results::Done;
}

