// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "Extension.h"
#include "Alerts.h"
#include "Results.h"
#include "../CppBase/StIO.h"



Uint32 Extension::sessionTicket( void )
{
// RFC 5077
// This is to resume a session.  It is obsolete
// in TLS 1.3.
// Ignore this.

StIO::putS( "Obsolete extension SessionTicket." );
return Results::Done;
}



/*
if( extType == ExtendedMasterSecretReserved )
  {
  // RFC 7627
  StIO::putS(
      "Obsolete extension ExtendedMasterSecret." );
  StIO::printF( "Last extended master secret: " );
  StIO::printFD( last );
  StIO::putLF();

  return Results::Done;
  }



if( extType == RenegotiationInfoReserved )
  {
  // RFC 5746
  StIO::putS(
      "Obsolete extension RenegotiationInfo." );
  StIO::printF( "Last RenegotiationInfo: " );
  StIO::printFD( last );
  StIO::putLF();

  return Results::Done;
  }
*/




Uint32 Extension::serverName( const CharBuf& data,
                              TlsMain& tlsMain )
{
// Server Name Indication (SNI)
// RFC 6066.

StIO::putS( "Extension is ServerName." );

const Int32 last = data.getLast();

if( last < 5 )
  return Results::Done;

//  {
//  StIO::putS(
//        "Extension ServerName too short." );
//  return Alerts::IllegalParameter;
//  }

// The list of names has a length.
Int32 nameListLength = data.getU8( 0 );
nameListLength <<= 8;
nameListLength |= data.getU8( 1 );

StIO::printF( "nameListLength: " );
StIO::printFD( nameListLength );
StIO::putLF();

// There is only one type so far in the enum,
// and it is host name.  Zero means hostname.
// A DNS type of name.
Uint8 nameType = data.getU8( 2 );
if( nameType != 0 )
  {
  // Was a new name type added in a later
  // RFC?
  StIO::putS(
       "Extension ServerName nameType not zero." );

  return Alerts::IllegalParameter;
  }

// This one name has a length.
Int32 nameLength = data.getU8( 3 );
nameLength <<= 8;
nameLength |= data.getU8( 4 );

StIO::printF( "nameLength: " );
StIO::printFD( nameLength );
StIO::putLF();

StIO::putS( "The server name is:" );

// This assumes there is only one name in
// the list.  It only gets the first one.
CharBuf serverNameBuf;
for( Int32 count = 5; count < last; count++ )
  {
  char c = data.getC( count );
  // Don't use ASCII from the space character
  // down to zero.
  if( c <= ' ' )
    {
    // "If the hostname labels contain only
    // US-ASCII characters, then the
    // client MUST ensure that labels are
    // separated only by the byte 0x2E,
    // representing the dot character"

    // A more thorough check would involve
    // making sure it looks like a DNS
    // host name.  But only a very limited
    // number of host names will be recognized
    // by a particular server, and it can
    // just say it doesn't recognize it.
    // some!Badly^formed$Name is just a string.
    // An unrecognized string.

    StIO::putS( "ExtenList bad host name." );
    return Alerts::IllegalParameter;
    }

  if( c == 127 )
    {
    StIO::putS( "ExtenList bad host name 127." );
    return Alerts::IllegalParameter;
    }

  if( (c & 0x80) != 0 )
    {
    // This is UTF8, so it would have to deal
    // with UTF8 correctly.  But I don't
    // want to deal with UTF8 here yet.
    StIO::putS( "ExtenList names are UTF8." );
    return Alerts::IllegalParameter;
    }

  StIO::putChar( c );
  serverNameBuf.appendChar( c );
  }

StIO::putLF();

tlsMain.setServerName( serverNameBuf );

// if( the server doesn't recognizes it...
//  {
//  StIO::putS( "Unrecognized server name:" );
// return Alerts::UnrecognizedName;
// }


return Results::Done;
}




Uint32 Extension::supportedVersions(
                              const CharBuf& data,
                              TlsMain& tlsMain,
                              bool isServerMsg )
{
// RFC 8446.

// The only supported version here is TLS 1.3.

StIO::putS( "Extension is SupportedVersions." );

const Int32 last = data.getLast();

if( isServerMsg )
  {
  if( last != 2 )
    {
    StIO::putS(
         "SupportedVersions for server != 2." );
    return Alerts::IllegalParameter;
    }

  Uint8 verHigh = data.getU8( 0 );
  StIO::printF( "Ver High: " );
  StIO::printFUD( verHigh );
  StIO::putLF();

  Uint8 verLow = data.getU8( 1 );
  StIO::printF( "Ver Low: " );
  StIO::printFUD( verLow );
  StIO::putLF();

  // Need to make sure I got an extension like
  // this.  What if it never sent the extension?

  if( !( (verHigh == 3) && (verLow == 4) ))
    throw "Server hello says not TLS 1.3.";

  return Results::Done;
  }


// It is a message from the client.
if( last < 3 )
  {
  // TLS 1.3 has to have this extension.
  StIO::putS(
         "SupportedVersions has no data." );
  return Alerts::IllegalParameter;
  }

Uint32 listLength = data.getU8( 0 );
StIO::putS( "SupportedVersions listLength:" );
StIO::printFUD( listLength );
StIO::putLF();

Int32 where = 1;
const Uint32 max = listLength / 2;
for( Uint32 count = 0; count < max; count++ )
  {
  Uint8 verHigh = data.getU8( where );
  where++;
  Uint8 verLow = data.getU8( where );
  where++;

  if( verHigh != 0x03 )
    {
    StIO::putS(
          "SupportedVersions verHigh is not 3." );
    return Alerts::IllegalParameter;
    }

  // TLS 1.3 is like SSL version 3.4.
  if( verLow == 0x04 )
    {
    tlsMain.setVersion13True();
    break;
    }
  }

if( !tlsMain.getIsVersion13())
  {
  StIO::putS( "Did not find TLS 1.3." );
  return Alerts::IllegalParameter;
  }

StIO::putS( "It has TLS 1.3." );

return Results::Done;
}




/*
if( extType == MaxFragmentLength )
  {
  // RFC 6066.
  // Section 4.

  StIO::putS( "Extension is MaxFragmentLength." );
  if( last < 2 )
    {
    StIO::putS(
           "MaxFragmentLength no data." );
    return Alerts::IllegalParameter;
    }

  // The server can respond to this by sending
  // the length that it accepted from the client.

  // "The extension_data field of this
  // extension SHALL contain:
  // enum{ 2^9(1), 2^10(2), 2^11(3),
  // 2^12(4), (255)

  // "If a server receives a maximum fragment
  // length negotiation request for a value
  // other than the allowed values,
  // it MUST abort the handshake with an
  // illegal_parameter alert."

  // That is one byte for the length, and
  // one byte for the data.

  return Results::Done;
  }



if( extType == StatusRequest )
  {
  StIO::putS( "Extension is StatusRequest." );
  // if( last < 2 )

  return Results::Done;
  }
*/


Uint32 Extension::supportedGroups(
                              const CharBuf& data,
                              TlsMain& tlsMain )
{
// SupportedGroups used to be
// elliptic_curves(10).
StIO::putS( "Extension is SupportedGroups." );

const Int32 last = data.getLast();

if( last < 4 )
  {
  StIO::putS( "SupportedGroups no data." );
  return Alerts::IllegalParameter;
  }

Uint32 listLength = data.getU8( 0 );
listLength <<= 8;
listLength |= data.getU8( 1 );

StIO::printF( "listLength: " );
StIO::printFUD( listLength );
StIO::putLF();

// If it doesn't find an acceptable one it
// should return insufficient_security(71).

Int32 where = 2;
const Uint32 max = listLength / 2;
for( Uint32 count = 0; count < max; count++ )
  {
  // Example bytes:
  // 00 0A 00 06 00 04 00 13 00 15
  // Length is 6, then the 3 values.

  Uint8 high = data.getU8( where );
  where++;
  Uint8 low = data.getU8( where );
  where++;

  StIO::printF( "high: " );
  StIO::printFUD( high );
  StIO::putLF();

  StIO::printF( "low: " );
  StIO::printFUD( low );
  StIO::putLF();

  // MCurve::NamedCrvX25519
  //  x25519(0x001D), x448(0x001E),
  if( (high == 0) && (low == 0x1D))
    {
    tlsMain.setHasX25519True();
    StIO::putS( "Has x25519." );
    }

  if( high == 1 )
    {
    // RFC 7919.
    // Finite Field Groups (DHE)
    // ffdhe2048(0x0100),
    // if( low == 0 )
    // ffdhe3072(0x0101),
    // ffdhe4096(0x0102),
    // ffdhe6144(0x0103),
    // ffdhe8192(0x0104),

    StIO::printF( "Finite Field low: " );
    StIO::printFUD( low );
    StIO::putLF();

    // Reserved Code Points
    // ffdhe_private_use(0x01FC..0x01FF),
    continue;
    }

  // "The named curves defined here are
  // those specified in SEC 2 Recommended
  // Elliptic Curve Domain Parameters."

  // Old ones:
  // NamedCurve;
  // sect163k1 (1),
  // sect163r1 (2),
  // sect163r2 (3),
  // sect193r1 (4),
  // sect193r2 (5),
  // sect233k1 (6),
  // sect233r1 (7),
  // sect239k1 (8),
  // sect283k1 (9),
  // sect283r1 (10),
  // sect409k1 (11),
  // sect409r1 (12),
  // sect571k1 (13),
  // sect571r1 (14),
  // secp160k1 (15),
  // secp160r1 (16),
  // secp160r2 (17),
  // secp192k1 (18),
  // secp192r1 (19),
  // secp224k1 (20),
  // secp224r1 (21),
  // secp256k1 (22),
  // secp256r1 (23),
  // secp384r1 (24),
  // secp521r1 (25),
  // reserved (0xFE00..0xFEFF),
  // arbitrary_explicit_prime_curves(0xFF01),
  // arbitrary_explicit_char2_curves(0xFF02),
  // (0xFFFF)
  // Reserved Code Points
  // ecdhe_private_use(0xFE00..0xFEFF),

  // For TLS 1.3 in Section 4.2.7.
  // Elliptic Curve Groups (ECDHE)
  // secp256r1(0x0017),
  // secp384r1(0x0018),
  // secp521r1(0x0019),

  //  x25519(0x001D)
  //  x448(0x001E),

  // Finite Field Groups (DHE)
  // ffdhe2048(0x0100),
  // ffdhe3072(0x0101),
  // ffdhe4096(0x0102),
  // ffdhe6144(0x0103),
  // ffdhe8192(0x0104),

  //Reserved Code Points
  // ffdhe_private_use(0x01FC..0x01FF),
  // ecdhe_private_use(0xFE00..0xFEFF),

  //      StIO::putS(
  //       "SupportedVersions verHigh is not 3." );
  // return Alerts::IllegalParameter;
  }

return Results::Done;
}



// The "signature_algorithms extension...
// applies to signatures in CertificateVerify
// messages".

// The signature_algorithms_cert can be
// broader, so it can say that it can also
// read old obsolete types of certificats,
// like things that wouldn't be allowed in
// the CertificateVerify message.

// "If no signature_algorithms_cert
// extension is present, then the
// signature_algorithms extension also
// applies to signatures appearing in
// certificates.



Uint32 Extension::signatureAlgorithms(
                              const CharBuf& data,
                              TlsMain& tlsMain )
{
// RFC 8017

// RFC 8446:

tlsMain.setNeedsWorkDone( true );

StIO::putS( "Extension is SignatureAlgorithms." );

const Int32 last = data.getLast();


// RSASSA-PKCS1-v1_5 is obsolete.

// RSASSA-PKCS1-v1_5 algorithms:
// rsa_pkcs1_sha256(0x0401),
// rsa_pkcs1_sha384(0x0501),
// rsa_pkcs1_sha512(0x0601),

// ECDSA algorithms:
// ecdsa_secp256r1_sha256(0x0403),
// ecdsa_secp384r1_sha384(0x0503),
// ecdsa_secp521r1_sha512(0x0603),

// RSASSA-PSS algorithms with public
// key OID rsaEncryption
// rsa_pss_rsae_sha256(0x0804),
// rsa_pss_rsae_sha384(0x0805),
// rsa_pss_rsae_sha512(0x0806),

// EdDSA algorithms
// ed25519(0x0807),
// ed448(0x0808),

// RSASSA-PSS algorithms with public key
// OID RSASSA-PSS
// rsa_pss_pss_sha256(0x0809),
// rsa_pss_pss_sha384(0x080a),
// rsa_pss_pss_sha512(0x080b),

// Legacy algorithms:
// rsa_pkcs1_sha1(0x0201),
// ecdsa_sha1(0x0203),

if( last < 4 )
  {
  StIO::putS( "SignatureAlgorithms no data." );
  return Alerts::IllegalParameter;
  }

Int32 listLength = data.getU8( 0 );
listLength <<= 8;
listLength |= data.getU8( 1 );

StIO::printF( "listLength: " );
StIO::printFD( listLength );
StIO::putLF();

Int32 where = 2;
const Int32 max = listLength / 2;
for( Int32 count = 0; count < max; count++ )
  {
  Uint8 byteHigh = data.getU8( where );
  where++;
  Uint8 byteLow = data.getU8( where );
  where++;

  StIO::printF( "byteHigh: " );
  StIO::printFUD( byteHigh );
  StIO::putLF();
  StIO::printF( "byteLow: " );
  StIO::printFUD( byteLow );
  StIO::putLF();

  //  StIO::putS( "something." );
  //  return Alerts::IllegalParameter;
  //  tlsParams.setVersion13True();
  }

// SignatureAlgorithms needs work.

return Results::Done;
}


Uint32 Extension::signatureAlgorithmsCert(
                              const CharBuf& data,
                              TlsMain& tlsMain )
{
StIO::putS(
        "SignatureAlgorithmsCert needs work." );
tlsMain.setNeedsWorkDone( true );

const Int32 last = data.getLast();

if( last < 4 )
  {
  StIO::putS(
           "SignatureAlgorithmsCert no data." );
  return Alerts::IllegalParameter;
  }

return Results::Done;
}




/*
if( extType == UseSrtp )
  {
  StIO::putS( "Extension is UseSrtp." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }


  return Results::Done;
  }



if( extType == HeartBeat )
  {
  StIO::putS( "Extension is HeartBeat." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }



if( extType == AppLayerProtocolNegot )
  {
  StIO::putS(
         "Extension is AppLayerProtocolNegot." );

  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }



if( extType == SignedCertTimeStamp )
  {
  StIO::putS( "Extension is SignedCertTimeStamp." );

  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }



if( extType == ClientCertType )
  {
  StIO::putS( "Extension is ClientCertType." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }



if( extType == ServerCertType )
  {
  StIO::putS( "Extension is ServerCertType." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }



if( extType == Padding )
  {
  StIO::putS( "Extension is Padding." );

  // The message body is just all zeros.
  // Uint8 zeroByte = data.getU8( where );

  return Results::Done;
  }



if( extType == PreSharedKey )
  {
  StIO::putS( "Extension is PreSharedKey." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }



if( extType == EarlyData )
  {
  StIO::putS( "Extension is EarlyData." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }



if( extType == Cookie )
  {
  StIO::putS( "Extension is Cookie." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }



if( extType == PskKeyExchModes )
  {
  // Pre-Shared Key Exchange Modes
  // RFC8446  section-4.2.9
  // "the client only supports the use
  // of PSKs with these modes
  // which restricts both the use of PSKs
  // offered in this ClientHello and
  // those which the server might supply
  // via NewSessionTicket."

  StIO::putS( "Extension is PskKeyExchModes." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }




if( extType == CertificateAuthorities )
  {
  StIO::putS(
         "Extension is CertificateAuthorities." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }



if( extType == OidFilters )
  {
  StIO::putS( "Extension is OidFilters." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }




if( extType == PostHandshakeAuth )
  {
  StIO::putS( "Extension is PostHandshakeAuth." );
  // if( last < 4 )
    // {
    // StIO::putS( "SignatureAlgCert no data." );
    // return Alerts::IllegalParameter;
    // }

  return Results::Done;
  }
*/






Uint32 Extension::keyShare(
                       const CharBuf& data,
                       TlsMain& tlsMain,
                       bool isServerMsg,
                       EncryptTls& encryptTls )
{
// See Named Curves in ECurve.h and MCurve.h.

StIO::putS( "Extension is KeyShare." );
  // RFC8446  section-4.2.8

const Int32 last = data.getLast();

if( last < 4 )
  {
  StIO::putS( "Key Share no data." );
  return Alerts::IllegalParameter;
  }

StIO::printF( "last keyshare: " );
StIO::printFD( last );
StIO::putLF();

Int32 where = 0;

// The ServerHello is not a list.  It is one entry.
// If the ClientHello sent a list, this would
// ignore all but the first one.

if( !isServerMsg )
  {
  StIO::printF( "It is a ClientHello list." );

  // If it is the ClientHello then it can send
  // a list of key shares.
  Int32 listLength = data.getU8( where );
  listLength <<= 8;
  where++;
  listLength |= data.getU8( where );
  where++;

  StIO::printF( "listLength: " );
  StIO::printFD( listLength );
  StIO::putLF();
  }

Int32 namedGroup = data.getU8( where );
namedGroup <<= 8;
where++;
namedGroup |= data.getU8( where );
where++;

// x25519
if( namedGroup == 0x001D )
  {
  StIO::printF( "Group is x25519." );
  StIO::putLF();
  }

if( namedGroup == 0x001E )
  {
  StIO::printF( "Group is x448." );
  StIO::putLF();
  }

// x25519
if( namedGroup != 0x001D )
  {
  StIO::putS( "namedGroup is not x25519." );
  }

StIO::printF( "namedGroup: " );
StIO::printFD( namedGroup );
StIO::putLF();

// Section 4.2.8.2
// ECDHE Parameters

// key_exchange:
Int32 keyExLen = data.getU8( where );
keyExLen <<= 8;
where++;
keyExLen |= data.getU8( where );
where++;

StIO::printF( "keyExLen: " );
StIO::printFD( keyExLen );
StIO::putLF();

if( namedGroup == 0x001D )
  {
  if( keyExLen != 32 )
    {
    StIO::printF( "keyExLen != 32. Length: " );
    StIO::printFD( keyExLen );
    StIO::putLF();
    return Alerts::IllegalParameter;
    }

  StIO::putS( "Getting 32 bytes for key." );

  ByteArray keyAr;
  keyAr.setSize( 32 );
  for( Int32 count = 0; count < 32; count++ )
    {
    keyAr.setU8( count, data.getU8( where ));
    where++;
    }

  Integer pubKey;
  tlsMain.mCurve.clampU( keyAr );
  tlsMain.mCurve.cArrayToInt(
                       keyAr, pubKey );

  if( isServerMsg )
    encryptTls.setSrvPubKey( pubKey );
  else
    encryptTls.setClientPubKey( pubKey );

  }

return Results::Done;
}
