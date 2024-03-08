// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




#include "CertExten.h"
#include "Alerts.h"
#include "Results.h"
#include "../CppBase/StIO.h"
#include "DerEncode.h"
#include "DerObjID.h"



// RFC 5280 Section 4.1.2.9.  Extensions


/*
Level: 2
Class ContextSpec
Context Specific value: 3

// A Sequence that contains Sequences.


// One Extension:
//   SequenceTag
//     ObjectIDTag
//     Boolean Critical might or
//                 might not be here.
//     OctetStringTag
// This OctetString "contains the DER
// encoding of an ASN.1 value corresponding
// to the extension type identified
// by extnID."

Level: 3
SequenceTag

Level: 4
SequenceTag

Level: 5
ObjectIDTag

Level: 5
OctetStringTag

Level: 4
SequenceTag

Level: 5
ObjectIDTag

Level: 5
OctetStringTag


Extensions  ::=  SEQUENCE SIZE (1..MAX)
 OF Extension



Extension  ::=  SEQUENCE  {
     extnID      OBJECT IDENTIFIER,
     critical    BOOLEAN DEFAULT FALSE,
"The encoding of a set value or sequence
 value shall not include an encoding for
 any component value which is equal to
 its default value."
So Boolean false is not there in an extension.


     extnValue   OCTET STRING
          -- contains the DER encoding of
          an ASN.1 value
          -- corresponding to the extension
          type identified
          -- by extnID
     }
*/



bool CertExten::parseOneExten( const CharBuf&
                            oneExtenSeqVal,
                            CharBuf& statusBuf )
{
StIO::putS( "parseOneExten top." );

Int32 lastSeqVal = oneExtenSeqVal.getLast();
StIO::printF( "lastSeqVal: " );
StIO::printFD( lastSeqVal );
StIO::putLF();

bool constructed = false;
DerEncode derEncode;
Int32 next = 0;
next = derEncode.readOneTag( oneExtenSeqVal,
                      next, constructed,
                      statusBuf, 0 );

if( derEncode.getTag() !=
                   DerEncode::ObjectIDTag )
  throw "CertExten not an objectID tag.";

CharBuf objID;
derEncode.getValue( objID );

CharBuf objIDOut;
DerObjID::makeFromCharBuf( objID,
                           objIDOut );

StIO::putS( "objIDOut:" );
StIO::putCharBuf( objIDOut );
StIO::putLF();

bool critical = false;

Uint8 boolCheck = oneExtenSeqVal.getU8( next );
if( boolCheck == DerEncode::BooleanTag )
  {
  StIO::putS( "Extension has a critical val." );

  // It is not supposed to be there if it
  // is the default value of false.
  // So just the fact that it is here means
  // it should be true.
  // critical    BOOLEAN DEFAULT FALSE,
  // value of false.  So if it's false it
  //_should_ be extnID followed by directly
  // by extnValue.
  // "The encoding of a set value or sequence
  // value shall not include an encoding for
  // any component value which is equal to
  // its default value."

  // In DER, the BOOLEAN type value true is:
  // 01 01 FF
  // True is any non zero value.
  // But for DER true can only be 0xFF.
  // But some non compliant things might
  // use any non zero value to mean true.

  next = derEncode.readOneTag(
                      oneExtenSeqVal,
                      next, constructed,
                      statusBuf, 0 );

  CharBuf boolVal;
  derEncode.getValue( boolVal );
  Int32 boolLen = boolVal.getLast();
  StIO::printF( "Critical bool length: " );
  StIO::printFD( boolLen );
  StIO::putLF();
  Uint8 testBool = boolVal.getU8( 0 );
  if( testBool != 0 )
    critical = true;

  }

// Now get the buf data.
derEncode.readOneTag( oneExtenSeqVal,
                      next, constructed,
                      statusBuf, 0 );

if( derEncode.getTag() !=
                   DerEncode::OctetStringTag )
  throw "CertExten data not Octet string.";

CharBuf octetString;
derEncode.getValue( octetString );

if( objIDOut.isEqual( basicConstraintObjID ))
  return parseBasicConstraints(
                    // octetString,
                    critical );

if( objIDOut.isEqual( keyUsageObjID ))
  return parseKeyUsage(
                    // const CharBuf& extenData,
                    critical );



StIO::putS( "CertExten: No matching extension." );
return true;
}





bool CertExten::parseBasicConstraints(
                    // const CharBuf& extenData,
                    const bool critical )
{
// RFC 5280 section 4.2.1.9.
//  Basic Constraints
// Object ID: 2.5.29.19

// "identifies whether the subject of the
//   certificate is a CA and the
//  maximum depth of valid certification
// paths"

// BasicConstraints ::= SEQUENCE {
// cA    BOOLEAN DEFAULT FALSE,
// pathLenConstraint INTEGER (0..MAX) OPTIONAL }

if( critical )
  {
  StIO::putS( "Basic constraints critical." );
  }

return true;
}



bool CertExten::parseKeyUsage(
                    // const CharBuf& extenData,
                    const bool critical )
{
// RFC 5280 section 4.2.1.3.
// Key Usage

// Object ID: 2.5.29.15

// The key usage extension defines the
// purpose (e.g., encipherment,
// signature, certificate signing) of
// the key contained in the
// certificate.

// "Conforming CAs MUST include this
// extension in certificates that
//   contain public keys that are used
// to validate digital signatures on
//   other public key certificates or
// CRLs.
//   SHOULD mark this extension as critical.

// KeyUsage ::= BIT STRING {
// digitalSignature        (0),
// nonRepudiation          (1),
//          -- recent editions of X.509 have
//          -- renamed this bit to
//             contentCommitment
// keyEncipherment         (2),
// dataEncipherment        (3),
// keyAgreement            (4),
// keyCertSign             (5),
// cRLSign                 (6),
// encipherOnly            (7),
// decipherOnly            (8) }


if( critical )
  {
  StIO::putS( "Basic key usage critical." );
  }

return true;
}
