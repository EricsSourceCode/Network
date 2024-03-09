// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "ExtenList.h"
#include "Extension.h"
#include "Alerts.h"
#include "Results.h"
#include "../CppBase/StIO.h"



// Client and Server extensions are almost
// the same, but there are differences.
// So the isServerMsg parameter is used for
// those differences.

Uint32 ExtenList::setFromMsg(
                    const CharBuf& allBytes,
                    const Int32 indexStart,
                    TlsMain& tlsMain,
                    bool isServerMsg,
                    EncryptTls& encryptTls )
{
try
{
Int32 index = indexStart;

const Int32 last = allBytes.getLast();

if( (indexStart + 3) >= last )
  {
  // If there are no extensions then it is
  // not TLS 1.3.
  StIO::putS( "Received no extensions at all." );
  return Alerts::DecodeError;
  }

// The whole list of extensions has a length.

Int32 extListLength = allBytes.getU8( index );
index++;
extListLength <<= 8;
extListLength |= allBytes.getU8( index );
index++;

StIO::printF( "Extension list length: " );
StIO::printFD( extListLength );
StIO::putLF();

// This is the index after getting the two bytes
// of the extListLength.

if( (index + extListLength) != last )
  {
  StIO::putS( "extListLength is not right." );
  return Alerts::DecodeError;
  }

CharBuf extListData;
for( Int32 count = 0; count < extListLength;
                                        count++ )
  {
  // if( index >= last )
    // break;

  extListData.appendU8( allBytes.getU8( index ));
  index++;
  }

const Int32 lastList = extListData.getLast();
if( lastList != extListLength )
  throw "lastList != extListLength";

CharBuf extenData;
Int32 extIndex = 0;
// while( true )
for( Int32 count = 0; count < 1000000; count++ )
  {
  // See RFC 4366 Section 2 for
  // General Extension Mechanisms.
  // All extensions have a type followed by
  // a length.

  StIO::putS( "\nNew extension." );
  Uint32 extType = extListData.getU8( extIndex );
  extIndex++;
  extType <<= 8;
  extType |= extListData.getU8( extIndex );
  extIndex++;

  Int32 extLength = extListData.getU8( extIndex );
  extIndex++;
  extLength <<= 8;
  extLength |= extListData.getU8( extIndex );
  extIndex++;

  StIO::printF( "extLength: " );
  StIO::printFD( extLength );
  StIO::putLF();

  // if( extLength == 0 )
    // An extension can be empty.

  extenData.clear();
  for( Int32 countByte = 0;
             countByte < extLength;
             countByte++ )
    {
    Uint8 aByte = extListData.getU8( extIndex );
    extenData.appendU8( aByte );
    extIndex++;
    }

  Uint32 result = setOneExt( extType, extenData,
                       tlsMain, isServerMsg,
                       encryptTls );
  if( result < Results::AlertTop )
    return result;

  if( extIndex >= lastList )
    {
    StIO::putLF();
    StIO::putLF();
    StIO::putS( "Break at end of ext list." );
    break;
    }
  }

return Results::Done;
}
catch( const char* in )
  {
  StIO::putS(
      "Exception in ExtenList.\n" );
  StIO::putS( in );
  return Alerts::DecodeError;
  }

catch( ... )
  {
  StIO::putS(
       "Exception in ExtenList." );
  return Alerts::DecodeError;
  }
}



Uint32 ExtenList::setOneExt(
                       const Uint32 extType,
                       const CharBuf& data,
                       TlsMain& tlsMain,
                       bool isServerMsg,
                       EncryptTls& encryptTls )
{
if( isServerMsg )
  {
  StIO::putS(
       "This is a message from the Server." );
  }
else
  {
  StIO::putS(
      "This is a message from the Client." );

  }
const Int32 last = data.getLast();
StIO::printF( "setOneExt last: " );
StIO::printFD( last );
StIO::putLF();

Extension extension;

if( extType == RecordSizeLimit )
  {
  StIO::putS(
      "Extension RecordSizeLimit." );

  return Results::Done;
  }

if( extType == SessionTicketReserved )
  return extension.sessionTicket();


if( extType == ExtendedMasterSecretReserved )
  {
  // Obsolete.  Zero length.
  // RFC 7627.
  // It is saying that, previous to TLS 1.3, it
  // wants to change the way that the
  // extended master secret computation
  // is done.  But TLS 1.3 changes all of that.

  StIO::putS(
      "Obsolete extension ExtendedMasterSecret." );

  return Results::Done;
  }

if( extType == RenegotiationInfoReserved )
  {
  // RFC 5746
  // Obsolete in TLS 1.3.
  // "This specification defines a TLS extension
  // to cryptographically tie renegotiations
  // to the TLS connections they are being
  // performed over, thus preventing this attack."

  StIO::putS(
      "Obsolete extension RenegotiationInfo." );

  return Results::Done;
  }


// Server Name Indication (SNI)
if( extType == ServerName )
  return extension.serverName( data, tlsMain );

if( extType == SupportedVersions )
  return extension.supportedVersions(
                  data, tlsMain, isServerMsg );


if( extType == MaxFragmentLength )
  {
  StIO::putS( "Extension is MaxFragmentLength." );
  return Results::Done;
  }

if( extType == StatusRequest )
  {
  StIO::putS( "Extension is StatusRequest." );
  return Results::Done;
  }

if( extType == SupportedGroups )
  return extension.supportedGroups(
                             data, tlsMain );

if( extType == SignatureAlgorithms )
  return extension.signatureAlgorithms(
                              data, tlsMain );


if( extType == SignatureAlgCert )
  return extension.signatureAlgorithmsCert(
                              data, tlsMain );


if( extType == UseSrtp )
  {
  StIO::putS( "Extension is UseSrtp." );
  return Results::Done;
  }

if( extType == HeartBeat )
  {
  StIO::putS( "Extension is HeartBeat." );
  return Results::Done;
  }

if( extType == AppLayerProtocolNegot )
  {
  StIO::putS(
         "Extension is AppLayerProtocolNegot." );

  return Results::Done;
  }

if( extType == SignedCertTimeStamp )
  {
  StIO::putS( "Extension is SignedCertTimeStamp." );
  return Results::Done;
  }

if( extType == ClientCertType )
  {
  StIO::putS( "Extension is ClientCertType." );
  return Results::Done;
  }

if( extType == ServerCertType )
  {
  StIO::putS( "Extension is ServerCertType." );
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
  return Results::Done;
  }

if( extType == EarlyData )
  {
  StIO::putS( "Extension is EarlyData." );
  return Results::Done;
  }

if( extType == Cookie )
  {
  StIO::putS( "Extension is Cookie." );
  return Results::Done;
  }

if( extType == PskKeyExchModes )
  {
  // RFC 8446 Section 4.2.9
  // Pre-Shared Key Exchange Modes

  //  "A client MUST provide a
  // psk_key_exchange_modes extension if it
  // offers a pre_shared_key extension."

  // One byte length, 1 byte for the mode.

  StIO::putS( "Extension is PskKeyExchModes." );
  return Results::Done;
  }

if( extType == CertificateAuthorities )
  {
  StIO::putS(
         "Extension is CertificateAuthorities." );
  return Results::Done;
  }

if( extType == OidFilters )
  {
  StIO::putS( "Extension is OidFilters." );
  return Results::Done;
  }

if( extType == PostHandshakeAuth )
  {
  // RFC 8446 Section 4.2.6.
  // "The post_handshake_auth extension is
  // used to indicate that a client
  // is willing to perform post-handshake
  // authentication.

  // It is zero length.

  StIO::putS( "Extension is PostHandshakeAuth." );
  return Results::Done;
  }

if( extType == KeyShare )
  return extension.keyShare( data, tlsMain,
                          isServerMsg,
                          encryptTls );


StIO::printF( "Extension type unknown: " );
StIO::printFUD( extType );
StIO::putLF();

StIO::printF( "Extension length: " );
StIO::printFD( last );
StIO::putLF();

// "Servers MUST ignore unrecognized
// extensions."

return Results::Done;
}




bool ExtenList::makeClHelloBuf(
                       CharBuf& outBuf,
                       TlsMain& tlsMain,
                       EncryptTls& encryptTls )
{
outBuf.clear();

// Put in a temporary place holder for the
// length of the whole list.

outBuf.appendU8( 0 ); // High byte
outBuf.appendU8( 0 ); // Little byte.

// Supported versions is required for TLS 1.3.

outBuf.appendU8( 0 ); // High byte of the type.
outBuf.appendU8( SupportedVersions );

// The length of the whole extension body.
outBuf.appendU8( 0 );
outBuf.appendU8( 3 );

// The length of the list.
outBuf.appendU8( 2 );

// For historical reasons, version 1.3 of
// TLS is like version 3.4 of SSL.

outBuf.appendU8( 3 ); // Version 3.4.
outBuf.appendU8( 4 );


// Server Name:

CharBuf domainBuf;
tlsMain.getServerName( domainBuf );

outBuf.appendU8( 0 );
outBuf.appendU8( ServerName );

Int32 serverNameLength = domainBuf.getLast();
if( serverNameLength < 1 )
  {
  StIO::putS( "ServerNameLength is zero." );
  return false;
  }

// The length of the whole extension body.
Int32 extLengthName = serverNameLength + 5;
outBuf.appendU8( (extLengthName >> 8) & 0xFF );
outBuf.appendU8( extLengthName & 0xFF );

// The length of the list of names.
Int32 nameListLength = serverNameLength + 3;
outBuf.appendU8( (nameListLength >> 8) & 0xFF );
outBuf.appendU8( nameListLength & 0xFF );

// You can only send one name for each name
// type.  RFC 6066.
// Use DNS host names.

// Name type is host_name
//           host_name(0), (255)
outBuf.appendU8( 0 );

// The length of the one name.
Int32 lengthHigh = serverNameLength >> 8;
outBuf.appendU8( lengthHigh & 0xFF );
outBuf.appendU8( serverNameLength & 0xFF );

// You can't use an IPv4 or IPv6 address as
// the domain name.
// This is to get the right X.509 certificate, etc.

outBuf.appendCharBuf( domainBuf );


// SupportedGroups
outBuf.appendU8( 0 ); // High byte of the type.
outBuf.appendU8( SupportedGroups );

// Length of the whole extension.
outBuf.appendU8( 0 ); // high byte.
outBuf.appendU8( 4 ); // Low byte.

// Length of the list.
outBuf.appendU8( 0 ); // high byte.
outBuf.appendU8( 2 ); // Low byte.

// Supports x25519:
outBuf.appendU8( 0 ); // high byte.
outBuf.appendU8( 0x1D );

// KeyShare )
outBuf.appendU8( 0 ); // High byte of the type.
outBuf.appendU8( KeyShare );

// Length of the whole extension.
outBuf.appendU8( 0 ); // high byte.
outBuf.appendU8( 38 ); // Low byte.

// The length of the list.
outBuf.appendU8( 0 ); // Length high byte.
outBuf.appendU8( 36 ); // Low byte.

// x25519
// namedGroup == 0x001D )
outBuf.appendU8( 0 ); // high byte.
outBuf.appendU8( 0x1D ); // Low byte.

// The length of one keyShareAr.
outBuf.appendU8( 0 ); // Length high byte.
outBuf.appendU8( 32 ); // Low byte.

// This is the client sending its public key.
Integer pubKey;
encryptTls.getClientPubKey( pubKey );

ByteArray keyShareAr;
tlsMain.mCurve.uCoordTo32Bytes(
                        pubKey, keyShareAr,
                        tlsMain.mod,
                        tlsMain.intMath );

Int32 keyShareSize = keyShareAr.getSize();
if( keyShareSize != 32 )
  {
  StIO::putS( "keyShareSize != 32" );
  return false;
  }

outBuf.appendCharArray( keyShareAr, 32 );


// RFC 8446:
// "If no signature_algorithms_cert extension is
// present, then the signature_algorithms
// extension also applies to signatures
// appearing in certificates."

// If this is not sent then the server has
// to respond with a MissingExtension alert.


// RFC 8446 section-4.2.3 Signature Algorithms

// RFC 8017

// I only have SHA256 right now.

// SignatureAlgorithms
outBuf.appendU8( 0 ); // High byte of the type.
outBuf.appendU8( SignatureAlgorithms );

// Length of the whole extension.
outBuf.appendU8( 0 ); // high byte.
outBuf.appendU8( 6 ); // Low byte.

// Length of the list.
outBuf.appendU8( 0 ); // high byte.
outBuf.appendU8( 4 ); // Low byte.

// RSASSA-PSS algorithms with public key
// OID rsaEncryption

// rsa_pss_rsae_sha256(0x0804),
outBuf.appendU8( 8 );
outBuf.appendU8( 4 );

// rsa_pss_rsae_sha384(0x0805),
// outBuf.appendU8( 8 );
// outBuf.appendU8( 5 );

// rsa_pss_rsae_sha512(0x0806),
// outBuf.appendU8( 8 );
// outBuf.appendU8( 6 );

// rsa_pkcs1_sha256(0x0401),
outBuf.appendU8( 4 );
outBuf.appendU8( 1 );

// rsa_pkcs1_sha384(0x0501),
// outBuf.appendU8( 5 );
// outBuf.appendU8( 1 );


// Legacy
// rsa_pkcs1_sha1(0x0201),
// outBuf.appendU8( 2 );
// outBuf.appendU8( 1 );

// ecdsa_secp256r1_sha256(0x0403),
// outBuf.appendU8( 4 );
// outBuf.appendU8( 3 );

// ecdsa_secp384r1_sha384(0x0503),
// outBuf.appendU8( 5 );
// outBuf.appendU8( 3 );

// Legacy
// ecdsa_sha1(0x0203),
// outBuf.appendU8( 2 );
// outBuf.appendU8( 3 );

// Must be very old legacy.
// outBuf.appendU8( 2 );
// outBuf.appendU8( 2 );


// rsa_pkcs1_sha512(0x0601),
// outBuf.appendU8( 6 );
// outBuf.appendU8( 1 );

// ecdsa_secp521r1_sha512(0x0603),
// outBuf.appendU8( 6 );
// outBuf.appendU8( 3 );


// The length of the whole list of extensions.
Int32 extenLen = outBuf.getLast();
extenLen -= 2; // After these length bytes.
outBuf.setU8( 0, (extenLen >> 8) & 0xFF );
outBuf.setU8( 1, extenLen & 0xFF );

return true;
}



bool ExtenList::makeSrvHelloBuf(
                       CharBuf& outBuf,
                       TlsMain& tlsMain,
                       EncryptTls& encryptTls )
{
outBuf.clear();

// Put in a temporary place holder for the
// length of the whole list.

outBuf.appendU8( 0 ); // High byte
outBuf.appendU8( 0 ); // Little byte.

// Supported versions is required for TLS 1.3.

outBuf.appendU8( 0 ); // High byte of the type.
outBuf.appendU8( SupportedVersions );

// The length of the whole extension body.
outBuf.appendU8( 0 );
outBuf.appendU8( 2 );

// This is not a list.  It is just
// these two bytes.
outBuf.appendU8( 3 ); // Version 3.4.
outBuf.appendU8( 4 );


// SupportedGroups is not in ServerHello.
// It goes in Encrypted Extensions.

// KeyShare )
outBuf.appendU8( 0 ); // High byte of the type.
outBuf.appendU8( KeyShare );

// Length of the whole extension.
outBuf.appendU8( 0 ); // high byte.
outBuf.appendU8( 36 ); // Low byte.

// There is no list in the server hello.
// The length of the list.
// outBuf.appendU8( 0 ); // Length high byte.
// outBuf.appendU8( 36 ); // Low byte.

// x25519
// namedGroup == 0x001D )
outBuf.appendU8( 0 ); // high byte.
outBuf.appendU8( 0x1D ); // Low byte.

// The length of one keyShareAr.
outBuf.appendU8( 0 ); // Length high byte.
outBuf.appendU8( 32 ); // Low byte.


// This is the server sending its public key.
Integer pubKey;
encryptTls.getSrvPubKey( pubKey );

ByteArray keyShareAr;
tlsMain.mCurve.uCoordTo32Bytes(
                        pubKey, keyShareAr,
                        tlsMain.mod,
                        tlsMain.intMath );

Int32 keyShareSize = keyShareAr.getSize();
if( keyShareSize != 32 )
  {
  StIO::putS( "keyShareSize != 32" );
  return false;
  }

outBuf.appendCharArray( keyShareAr, 32 );

// The length of the whole list of extensions.
Int32 extenLen = outBuf.getLast();
extenLen -= 2; // After these length bytes.
outBuf.setU8( 0, (extenLen >> 8) & 0xFF );
outBuf.setU8( 1, extenLen & 0xFF );

return true;
}
