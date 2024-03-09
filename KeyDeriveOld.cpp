/*


// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#include "KeyDerive.h"
#include "../CppBase/StIO.h"



void KeyDerive::extract( CharBuf& prk,
                         const CharBuf& salt,
                         const CharBuf& ikm )
{
// prk: pseudo random Key.
// ikm: Input Keying Material.

sha256.hMac( prk, salt, ikm );
}




// RFC 5869 section-2.3

void KeyDerive::expand( CharBuf& T1,
                        // CharBuf& T2,
                        // CharBuf& T3,
                        const CharBuf& prk,
                        const CharBuf& info )
                        // const Int32 L )
{
StIO::putLF();
StIO::putS( "Top of expand." );
StIO::putS( "info:" );

info.showHex();
StIO::putLF();
// okm: Output Key Material
// prk:  Pseudorandom Key
// info: context and application specific
//       See RFC 8446 section 7.

// L is Length in bytes of output keying material
// (OKM).

// if( L > 32 )
  // throw "KeyDerive::expand Length > 32.";

// The hash is 32 bytes for Sha256.

//   HKDF-Expand(PRK, info, L) -> OKM
//   N = ceil(L/HashLen)

// Int32 N = L / 32;


// T = T(1) | T(2) | T(3) | ... | T(N)
// OKM = first L octets of T

//   T(0) = empty string (zero length)
//   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
//   T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
//   T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
//   ...

T1.setSize( 64 );
// T2.setSize( 1024 );
// T3.setSize( 1024 );

T1.clear();
// T2.clear();
// T3.clear();

CharBuf T; // Empty string for T0.
T.setSize( 1024 );

T.appendCharBuf( info );
T.appendU8( 0x01 );

sha256.hMac( T1, prk, T );

// T.copy( T1 );
// T.appendCharBuf( info );
// T.appendU8( 0x02 );

// sha256.hMac( T2, prk, T );

// T.copy( T2 );
// T.appendCharBuf( info );
// T.appendU8( 0x03 );

// sha256.hMac( T3, prk, T );
}


void KeyDerive::hkdfExpandLabel( CharBuf& outBuf,
                       const CharBuf& secret,
                       const CharBuf& label,
                       const CharBuf& context,
                       const Int32 length )
{
// StIO::putS( "Top of hkdfExpandLabel." );

// RFC 8446 Section 7.1

// For Sha256 in TLS 1.3 it never used more
// that 32 bytes.

if( length > 32 )
  throw "KeyDerive::hkdfExpandLabel length > 32";


CharBuf hkdfLabel;
Uint8 highByte = (length >> 8) & 0xFF;
Uint8 lowByte = length & 0xFF;
hkdfLabel.appendU8( highByte );
hkdfLabel.appendU8( lowByte );

Int32 labelLength = label.getLast();
labelLength += 6;
hkdfLabel.appendU8( labelLength & 0xFF );
hkdfLabel.appendCharPt( "tls13 " );
hkdfLabel.appendCharBuf( label );

Int32 contextLength = context.getLast();
hkdfLabel.appendU8( contextLength & 0xFF );
hkdfLabel.appendCharBuf( context );

CharBuf T1;
// CharBuf T2;
// CharBuf T3;

expand( T1, secret, hkdfLabel ); // , length );

// The way this is being used in TLS 1.3 it
// doesn't get more than the first 32 bytes
// for SHA256.

outBuf.copy( T1 );
}



void KeyDerive::deriveSecret( CharBuf& outBuf,
                     const CharBuf& secret,
                     const CharBuf& label,
                     const CharBuf& messages )
{
CharBuf msgHash;
sha256.processAllBlocks( messages );
sha256.getHash( msgHash );

StIO::putS( "derivedSecret() hash: " );
msgHash.showHex();
StIO::putLF();

// HKDF-Expand-Label(Secret, Label,
//            Transcript-Hash(Messages),
//            Hash.length )

const Int32 hashLength = 32;

hkdfExpandLabel( outBuf, secret, label,
                 msgHash, hashLength );

}




void KeyDerive::setHandshakeKeys(
                       TlsMain& tlsMain,
                       Integer& sharedS,
                       EncryptTls& encryptTls )
{
try
{
// RFC 8446 Section 7
// Cryptographic Computations

// Follow along with the example in
// RFC 8448 section 3
// Simple 1-RTT Handshake.

StIO::putS( "setHandshakeKeys()" );

CharBuf prk;  // Pseudo Random Key
CharBuf salt;
CharBuf ikm;  // Input Keying Material

salt.fillBytes( 0, 32 );

// This ikm would be the preshared key.
// But there is no preshared key here,
// so it is all zeros.

ikm.fillBytes( 0, 32 );
extract( prk, salt, ikm );

StIO::putS( "Early Secret:" );
prk.showHex();
// secret (32 octets):  33 ad 0a 1c 60 7e
// c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3
// 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a


CharBuf outBuf;
CharBuf messages; // Empty for this one.

// Derive-Secret(., "derived", "")
deriveSecret( outBuf, prk, "derived", messages );

StIO::putS( "First derived secret:" );
outBuf.showHex();
StIO::putLF();


// First Derived Secret:
salt.copy( outBuf );

// Shared Key:
CharBuf sharedBytes;
ByteArray sharedBytesArray;
tlsMain.mCurve.uCoordTo32Bytes( sharedS,
                        sharedBytesArray,
                        tlsMain.mod,
                        tlsMain.intMath );

sharedBytes.appendCharArray( sharedBytesArray, 32 );
ikm.copy( sharedBytes );

extract( prk, salt, ikm );

StIO::putS( "Handshake secret:" );
prk.showHex();
StIO::putLF();

CharBuf clHelloMsg;
CharBuf srvHelloMsg;

tlsMain.getClientHelloMsg( clHelloMsg );
tlsMain.getServerHelloMsg( srvHelloMsg );

StIO::putS( "clHelloMsg:" );
clHelloMsg.showHex();
StIO::putLF();

StIO::putS( "srvHelloMsg:" );
srvHelloMsg.showHex();
StIO::putLF();

CharBuf msgHash;
msgHash.copy( clHelloMsg );
msgHash.appendCharBuf( srvHelloMsg );

deriveSecret( outBuf, prk, "c hs traffic",
                                  msgHash );

CharBuf clHsTraffic;
clHsTraffic.copy( outBuf );

StIO::putS( "c hs traffic:" );
clHsTraffic.showHex();
StIO::putLF();

outBuf.clear();
deriveSecret( outBuf, prk, "s hs traffic",
                                  msgHash );

CharBuf srvHsTraffic;
srvHsTraffic.copy( outBuf );
StIO::putS( "s hs traffic:" );
srvHsTraffic.showHex();
StIO::putLF();

outBuf.clear();
// Derive-Secret(., "derived", "")
deriveSecret( outBuf, prk, "derived", messages );

StIO::putS( "Derived Secret for Master:" );
outBuf.showHex();
StIO::putLF();

salt.copy( outBuf );
ikm.fillBytes( 0, 32 );
extract( outBuf, salt, ikm );

extractSecretMaster.copy( outBuf );
StIO::putS( "Extract Secret Master:" );
extractSecretMaster.showHex();
StIO::putLF();

CharBuf clTrafficKey;
hkdfExpandLabel( clTrafficKey, clHsTraffic,
                 "key", "", 16 );

// Only use the first 16 bytes.
clTrafficKey.truncateLast( 16 );

StIO::putS( "clTrafficKey:" );
clTrafficKey.showHex();
StIO::putLF();

encryptTls.aesClientWrite.setKey(
                         clTrafficKey, 16 );


CharBuf srvTrafficKey;
hkdfExpandLabel( srvTrafficKey, srvHsTraffic,
                 "key", "", 16 );

srvTrafficKey.truncateLast( 16 );

StIO::putS( "srvTrafficKey:" );
srvTrafficKey.showHex();
StIO::putLF();

tlsMain.aesServerWrite.setKey(
                           srvTrafficKey, 16 );


// The key has been changed so set it to zero.
tlsMain.setClWriteRecSequenceZero();
tlsMain.setSrvWriteRecSequenceZero();


// RFC 8446 Section 5.3, Per-Record Nonce.
//   sender_write_iv  = HKDF-Expand-Label(Secret,
// "iv", "", iv_length)

// IV is 12 bytes for AES 128.
// This is creating the static part
// of the IV.

CharBuf srvWriteStatIV;
hkdfExpandLabel( srvWriteStatIV, srvHsTraffic,
                 "iv", "", 12 );
srvWriteStatIV.truncateLast( 12 );

StIO::putS( "srvWriteStatIV:" );
srvWriteStatIV.showHex();
StIO::putLF();


CharBuf clWriteStatIV;
hkdfExpandLabel( clWriteStatIV, clHsTraffic,
                 "iv", "", 12 );
clWriteStatIV.truncateLast( 12 );

StIO::putS( "clWriteStatIV:" );
clWriteStatIV.showHex();
StIO::putLF();

tlsMain.setStaticClWriteIV( clWriteStatIV );
tlsMain.setStaticSrvWriteIV( srvWriteStatIV );

}
catch( const char* in )
  {
  StIO::putS(
    "Exception KeyDerive.setHandshakeKeys.\n" );
  StIO::putS( in );
  // return false;
  }
catch( ... )
  {
  const char* in = "Unknown exception in "
          "KeyDerive.setHandshakeKeys.\n";

  StIO::putS( in );
  // return false;
  }
}




void KeyDerive::setAppDataKeys(
                           TlsMain& tlsMain )
{
try
{
StIO::putS( "setAppDataKeys" );

// This was set in setHandshakeKeys().
StIO::putS( "Extract Secret Master:" );
extractSecretMaster.showHex();
StIO::putLF();
StIO::putLF();


CharBuf messages;

// Concatenate these messages together.
CharBuf clHelloMsg;
CharBuf srvHelloMsg;
CharBuf encExtenMsg;
CharBuf certificateMsg;
CharBuf certVerifyMsg;
CharBuf srvWriteFinishedMsg;
CharBuf clWriteFinishedMsg;

tlsMain.getClientHelloMsg( clHelloMsg );
tlsMain.getServerHelloMsg( srvHelloMsg );
tlsMain.getEncExtenMsg( encExtenMsg );
tlsMain.getCertificateMsg( certificateMsg );
tlsMain.getCertVerifyMsg( certVerifyMsg );
tlsMain.getSrvWriteFinishedMsg(
                       srvWriteFinishedMsg );
tlsMain.getClWriteFinishedMsg(
                       clWriteFinishedMsg );
tlsMain.getClWriteFinishedMsg(
                       clWriteFinishedMsg );

StIO::putS( "clHelloMsg:" );
clHelloMsg.showHex();
StIO::putLF();

StIO::putS( "srvHelloMsg:" );
srvHelloMsg.showHex();
StIO::putLF();

StIO::putS( "encExtenMsg:" );
encExtenMsg.showHex();
StIO::putLF();

StIO::putS( "certificateMsg:" );
certificateMsg.showHex();
StIO::putLF();

StIO::putS( "certVerifyMsg:" );
certVerifyMsg.showHex();
StIO::putLF();

StIO::putS( "srvWriteFinishedMsg:"  );
srvWriteFinishedMsg.showHex();
StIO::putLF();

StIO::putS( "clWriteFinishedMsg:" );
clWriteFinishedMsg.showHex();
StIO::putLF();


CharBuf msgHash;
msgHash.copy( clHelloMsg );
msgHash.appendCharBuf( srvHelloMsg );
msgHash.appendCharBuf( encExtenMsg );
msgHash.appendCharBuf( certificateMsg );
msgHash.appendCharBuf( certVerifyMsg );
msgHash.appendCharBuf( srvWriteFinishedMsg );

// This is not included:
// msgHash.appendCharBuf( clWriteFinishedMsg );

CharBuf outBuf;
CharBuf prk;
// CharBuf salt;
// CharBuf ikm;

prk.copy( extractSecretMaster );

deriveSecret( outBuf, prk, "s ap traffic",
                                  msgHash );

CharBuf srvAppDataTraffic;
srvAppDataTraffic.copy( outBuf );

StIO::putS( "s ap traffic:" );
srvAppDataTraffic.showHex();
StIO::putLF();

deriveSecret( outBuf, prk, "c ap traffic",
                                  msgHash );

CharBuf clAppDataTraffic;
clAppDataTraffic.copy( outBuf );

StIO::putS( "c ap traffic:" );
clAppDataTraffic.showHex();
StIO::putLF();



CharBuf clTrafficKey;
hkdfExpandLabel( clTrafficKey, clAppDataTraffic,
                 "key", "", 16 );

// Only use the first 16 bytes.
clTrafficKey.truncateLast( 16 );

StIO::putS( "clTrafficKey:" );
clTrafficKey.showHex();
StIO::putLF();

tlsMain.aesClientWrite.setKey( clTrafficKey, 16 );


CharBuf srvTrafficKey;
hkdfExpandLabel( srvTrafficKey,
             srvAppDataTraffic, "key", "", 16 );

srvTrafficKey.truncateLast( 16 );

StIO::putS( "srvTrafficKey:" );
srvTrafficKey.showHex();
StIO::putLF();

tlsMain.aesServerWrite.setKey(
                           srvTrafficKey, 16 );


// The key has been changed so set it to zero.
tlsMain.setClWriteRecSequenceZero();
tlsMain.setSrvWriteRecSequenceZero();


// RFC 8446 Section 5.3, Per-Record Nonce.
//   sender_write_iv  = HKDF-Expand-Label(Secret,
// "iv", "", iv_length)

// IV is 12 bytes for AES 128.
// This is creating the static part
// of the IV.

CharBuf srvStatIV;
hkdfExpandLabel( srvStatIV, srvAppDataTraffic,
                 "iv", "", 12 );
srvStatIV.truncateLast( 12 );

StIO::putS( "srvStatIV:" );
srvStatIV.showHex();
StIO::putLF();


CharBuf clStatIV;
hkdfExpandLabel( clStatIV, clAppDataTraffic,
                 "iv", "", 12 );
clStatIV.truncateLast( 12 );

StIO::putS( "clStatIV:" );
clStatIV.showHex();
StIO::putLF();

tlsMain.setStaticClWriteIV( clStatIV );
tlsMain.setStaticSrvWriteIV( srvStatIV );

}
catch( const char* in )
  {
  StIO::putS(
    "Exception KeyDerive.setAppDataKeys.\n" );
  StIO::putS( in );
  // return false;
  }
catch( ... )
  {
  const char* in = "Unknown exception in "
          "KeyDerive.setAppDataKeys.\n";

  StIO::putS( in );
  // return false;
  }
}





void KeyDerive::setDiffHelmOnClient(
                              TlsMain& tlsMain,
                              Integer& sharedS )
{
// See RFC 7748 Section 6.1.

StIO::putS( "setDiffHelmOnClient" );

Integer serverPubKey;
Integer clientPrivKey;
tlsMain.getSrvPubKey( serverPubKey );
tlsMain.getClientPrivKey( clientPrivKey );

tlsMain.mCurve.montLadder1(
                     sharedS, serverPubKey,
                     clientPrivKey,
                     tlsMain.intMath,
                     tlsMain.mod );

if( sharedS.isZero())
  throw "KeyDerive sharedS.isZero.";

ByteArray sharedBytes;
tlsMain.mCurve.uCoordTo32Bytes( sharedS,
                        sharedBytes,
                        tlsMain.mod,
                        tlsMain.intMath );

if( sharedBytes.getSize() != 32 )
  throw "KeyDerive sharedBytes != 32";

CharBuf sharedBuf;
sharedBuf.appendCharArray( sharedBytes, 32 );


StIO::putS( "Shared Key:" );
sharedBuf.showHex();
StIO::putLF();
}



void KeyDerive::setDiffHelmOnServer(
                              TlsMain& tlsMain,
                              Integer& sharedS )
{
// See RFC 7748 Section 6.1.

StIO::putS( "setDiffHelmOnServer" );

Integer clientPubKey;
Integer serverPrivKey;
tlsMain.getClientPubKey( clientPubKey );
tlsMain.getSrvPrivKey( serverPrivKey );

tlsMain.mCurve.montLadder1(
                     sharedS, clientPubKey,
                     serverPrivKey,
                     tlsMain.intMath,
                     tlsMain.mod );

if( sharedS.isZero())
  throw "KeyDerive sharedS.isZero.";

ByteArray sharedBytes;
tlsMain.mCurve.uCoordTo32Bytes( sharedS,
                        sharedBytes,
                        tlsMain.mod,
                        tlsMain.intMath );

if( sharedBytes.getSize() != 32 )
  throw "KeyDerive sharedBytes != 32";

CharBuf sharedBuf;
sharedBuf.appendCharArray( sharedBytes, 32 );

StIO::putS( "Shared Key:" );
sharedBuf.showHex();
StIO::putLF();
}

*/
