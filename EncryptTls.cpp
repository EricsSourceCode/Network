// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#include "EncryptTls.h"
#include "../CppBase/StIO.h"
#include "TlsOuterRec.h"




void EncryptTls::extract( CharBuf& prk,
                         const CharBuf& salt,
                         const CharBuf& ikm )
{
// prk: pseudo random Key.
// ikm: Input Keying Material.

sha256.hMac( prk, salt, ikm );
}




// RFC 5869 section-2.3

void EncryptTls::expand( CharBuf& T1,
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
  // throw "EncryptTls::expand Length > 32.";

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


void EncryptTls::hkdfExpandLabel( CharBuf& outBuf,
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
  throw "EncryptTls::hkdfExpandLabel length > 32";


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



void EncryptTls::deriveSecret( CharBuf& outBuf,
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




void EncryptTls::setHandshakeKeys(
                       TlsMain& tlsMain,
                       Integer& sharedS )
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
CharBuf emptyMessages; // Empty for this one.

// Derive-Secret(., "derived", "")
deriveSecret( outBuf, prk, "derived",
                            emptyMessages );

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

sharedBytes.appendCharArray(
                       sharedBytesArray, 32 );
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

tlsMain.setClHsTraffic( clHsTraffic );

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
deriveSecret( outBuf, prk, "derived",
                              emptyMessages );

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

aesClientWrite.setKey( clTrafficKey, 16 );

CharBuf srvTrafficKey;
hkdfExpandLabel( srvTrafficKey, srvHsTraffic,
                 "key", "", 16 );

srvTrafficKey.truncateLast( 16 );

StIO::putS( "srvTrafficKey:" );
srvTrafficKey.showHex();
StIO::putLF();

aesServerWrite.setKey( srvTrafficKey, 16 );


// The key has been changed so set it to zero.
setClWriteRecSequenceZero();
setSrvWriteRecSequenceZero();


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

setStaticClWriteIV( clWriteStatIV );
setStaticSrvWriteIV( srvWriteStatIV );
}
catch( const char* in )
  {
  StIO::putS(
    "Exception EncryptTls.setHandshakeKeys.\n" );
  StIO::putS( in );
  // return false;
  }
catch( ... )
  {
  const char* in = "Unknown exception in "
          "EncryptTls.setHandshakeKeys.\n";

  StIO::putS( in );
  // return false;
  }
}



void EncryptTls::makeMsgTranscript2(
                       CharBuf& transcript,
                       TlsMain& tlsMain )
{
StIO::putS( "\n\nmakeMsgTranscript2" );

// This was set in setHandshakeKeys().
// StIO::putS( "Extract Secret Master:" );
// extractSecretMaster.showHex();
// StIO::putLF();
// StIO::putLF();

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

/*
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
*/


CharBuf msgHash;
msgHash.copy( clHelloMsg );
msgHash.appendCharBuf( srvHelloMsg );
msgHash.appendCharBuf( encExtenMsg );
msgHash.appendCharBuf( certificateMsg );
msgHash.appendCharBuf( certVerifyMsg );
msgHash.appendCharBuf( srvWriteFinishedMsg );

// This is not included:
// msgHash.appendCharBuf( clWriteFinishedMsg );

transcript.copy( msgHash );

StIO::putS( "End of makeMsgTranscript2\n\n" );
}



void EncryptTls::setAppDataKeys(
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
makeMsgTranscript2( messages, tlsMain );


CharBuf outBuf;
CharBuf prk;
// CharBuf salt;
// CharBuf ikm;

prk.copy( extractSecretMaster );

deriveSecret( outBuf, prk, "s ap traffic",
                                 messages );

CharBuf srvAppDataTraffic;
srvAppDataTraffic.copy( outBuf );

StIO::putS( "s ap traffic:" );
srvAppDataTraffic.showHex();
StIO::putLF();

deriveSecret( outBuf, prk, "c ap traffic",
                                 messages );

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

aesClientWrite.setKey( clTrafficKey, 16 );


CharBuf srvTrafficKey;
hkdfExpandLabel( srvTrafficKey,
             srvAppDataTraffic, "key", "", 16 );

srvTrafficKey.truncateLast( 16 );

StIO::putS( "srvTrafficKey:" );
srvTrafficKey.showHex();
StIO::putLF();

aesServerWrite.setKey( srvTrafficKey, 16 );


// The key has been changed so set it to zero.
setClWriteRecSequenceZero();
setSrvWriteRecSequenceZero();


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

setStaticClWriteIV( clStatIV );
setStaticSrvWriteIV( srvStatIV );

}
catch( const char* in )
  {
  StIO::putS(
    "Exception EncryptTls.setAppDataKeys.\n" );
  StIO::putS( in );
  // return false;
  }
catch( ... )
  {
  const char* in = "Unknown exception in "
          "EncryptTls.setAppDataKeys.\n";

  StIO::putS( in );
  // return false;
  }
}





void EncryptTls::setDiffHelmOnClient(
                              TlsMain& tlsMain,
                              Integer& sharedS )
{
// See RFC 7748 Section 6.1.

StIO::putS( "setDiffHelmOnClient" );


tlsMain.mCurve.montLadder1(
                     sharedS, servPubKey,
                     clientPrivKey,
                     tlsMain.intMath,
                     tlsMain.mod );

if( sharedS.isZero())
  throw "EncryptTls sharedS.isZero.";

ByteArray sharedBytes;
tlsMain.mCurve.uCoordTo32Bytes( sharedS,
                        sharedBytes,
                        tlsMain.mod,
                        tlsMain.intMath );

if( sharedBytes.getSize() != 32 )
  throw "EncryptTls sharedBytes != 32";

CharBuf sharedBuf;
sharedBuf.appendCharArray( sharedBytes, 32 );


StIO::putS( "Shared Key:" );
sharedBuf.showHex();
StIO::putLF();
}



void EncryptTls::setDiffHelmOnServer(
                              TlsMain& tlsMain,
                              Integer& sharedS )
{
// See RFC 7748 Section 6.1.

StIO::putS( "setDiffHelmOnServer" );

tlsMain.mCurve.montLadder1(
                     sharedS, clientPubKey,
                     servPrivKey,
                     tlsMain.intMath,
                     tlsMain.mod );

if( sharedS.isZero())
  throw "EncryptTls sharedS.isZero.";

ByteArray sharedBytes;
tlsMain.mCurve.uCoordTo32Bytes( sharedS,
                        sharedBytes,
                        tlsMain.mod,
                        tlsMain.intMath );

if( sharedBytes.getSize() != 32 )
  throw "EncryptTls sharedBytes != 32";

CharBuf sharedBuf;
sharedBuf.appendCharArray( sharedBytes, 32 );

StIO::putS( "Shared Key:" );
sharedBuf.showHex();
StIO::putLF();
}



/*
void EncryptTls::srvWriteEncryptCharBuf(
                    const CharBuf& plainBuf,
                    CharBuf& cipherBuf )
{
aesServerWrite.encryptCharBuf(
                          plainBuf,
                          IV,
                          aaData,
                          cipherBuf );
}
*/


void EncryptTls::srvWriteDecryptCharBuf(
                     const CharBuf& cipherBuf,
                     CharBuf& plainBuf )
{
Uint64 sequence = getClWriteRecSequence();

// Increment the sequence for the next
// record.
incrementClWriteRecSequence();

CharBuf sequenceBuf;
sequenceBuf.fillBytes( 0, 4 );

// Big endian.
sequenceBuf.appendU64( sequence );

if( sequenceBuf.getLast() != 12 )
throw "sequenceBuf != 12 bytes.";

CharBuf statSrvWriteIV;
getStaticSrvWriteIV( statSrvWriteIV );

sequenceBuf.xorFrom( statSrvWriteIV );

CharBuf additionalData;
additionalData.appendU8(
             TlsOuterRec::ApplicationData );
additionalData.appendU8( 3 );
additionalData.appendU8( 3 );

Int32 lengthRec = cipherBuf.getLast();
Uint8 highByte = (lengthRec >> 8) & 0xFF;
Uint8 lowByte = lengthRec & 0xFF;
additionalData.appendU8( highByte );
additionalData.appendU8( lowByte );

aesServerWrite.decryptCharBuf(
                         cipherBuf,
                         sequenceBuf, // IV,
                         additionalData, //aaData,
                         plainBuf );

}


/*
void EncryptTls::clWriteEncryptCharBuf(
                    const CharBuf& plainBuf,
                    const CharBuf& IV,
                    const CharBuf& aaData,
                    CharBuf& cipherBuf )
{
aesClientWrite.encryptCharBuf(
                          plainBuf,
                          IV,
                          aaData,
                          cipherBuf );
}
*/


void EncryptTls::clWriteDecryptCharBuf(
                     const CharBuf& cipherBuf,
                     CharBuf& plainBuf )
{
Uint64 sequence = getSrvWriteRecSequence();

// Increment the sequence for the next
// record.
incrementSrvWriteRecSequence();

CharBuf sequenceBuf;
sequenceBuf.fillBytes( 0, 4 );

// Big endian.
sequenceBuf.appendU64( sequence );

if( sequenceBuf.getLast() != 12 )
    throw "sequenceBuf != 12 bytes.";

CharBuf statClWriteIV;
getStaticClWriteIV( statClWriteIV );

sequenceBuf.xorFrom( statClWriteIV );

CharBuf additionalData;
additionalData.appendU8(
              TlsOuterRec::ApplicationData );
additionalData.appendU8( 3 );
additionalData.appendU8( 3 );

Int32 lengthRec = cipherBuf.getLast();
Uint8 highByte = (lengthRec >> 8) & 0xFF;
Uint8 lowByte = lengthRec & 0xFF;
additionalData.appendU8( highByte );
additionalData.appendU8( lowByte );

aesClientWrite.decryptCharBuf(
                         cipherBuf,
                         sequenceBuf, // IV,
                         additionalData, //aaData,
                         plainBuf );

}



void EncryptTls::makeClFinishedMsg(
                           TlsMain& tlsMain,
                           CharBuf& finished )
{
 ===========
// RFC 8446 section-4.4.4
// Finished

// BaseKey

//   finished_key =
//     HKDF-Expand-Label(BaseKey,
//     "finished", "", Hash.length)

// verify_data =
//          HMAC(finished_key,
//          Transcript-Hash(Handshake Context,
//                      Certificate*,
//                      CertificateVerify*))
//   * Only included if present.


//   The following table defines the Handshake
//   Context and MAC Base Key
//   for each scenario:

//   | Mode      | Handshake Context       |
//       Base Key                    |

//   | Server    | ClientHello ... later
//   | server_handshake_traffic_   |
//   |           | of EncryptedExtensions/ |
// secret                      |
//   |           | CertificateRequest      |
//                             |
//   |           |                         |
//                             |
//   | Client    | ClientHello ... later   |
// client_handshake_traffic_   |
//   |           | of server               |
// secret                      |
//   |           | Finished/EndOfEarlyData |
//                             |
//   |           |                         |
//                             |
//   | Post-     | ClientHello ... client  |
// client_application_traffic_ |
//  | Handshake | Finished +              |
// secret_N                    |
//    |           | CertificateRequest      |
//                             |

}
