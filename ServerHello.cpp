// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#include "ServerHello.h"
#include "Alerts.h"
#include "Results.h"

#include "../CryptoBase/Randomish.h"

#include "../CppBase/StIO.h"



ServerHello::ServerHello( void )
{
}


ServerHello::ServerHello( const ServerHello& in )
{
if( in.testForCopy )
  return;

throw "ServerHello copy constructor called.";
}



ServerHello::~ServerHello( void )
{
}



Uint32 ServerHello::parseBuffer(
                        const CharBuf& inBuf,
                        TlsMain& tlsMain,
                        EncryptTls& encryptTls )
{
try
{
// All of the msgBytes will be in the hash
// later.
msgBytes.copy( inBuf );

// const Int32 last = msgBytes.getLast();

StIO::putS( "Parsing ServerHello." );

// The handshake type is 1 byte,
// length is 3 bytes, then
// Uint8 legacyHigh = msgBytes.getU8( 4 );
// Uint8 legacyLow = msgBytes.getU8( 5 );

CharBuf randBytes;

Int32 index = 6;
for( Int32 count = 0; count < 32; count++ )
  {
  randBytes.appendU8( msgBytes.getU8( index ));
  index++;
  }

tlsMain.setServerRandom( randBytes );

const Uint8 sessionIDLength = msgBytes.getU8( 38 );

StIO::printF( "sessionIDLength: " );
StIO::printFUD( sessionIDLength );
StIO::putLF();

// The server sends back the session ID that
// the client sent.


index = 39;

CharBuf sessionID;
for( Uint32 countID = 0;
            countID < sessionIDLength; countID++ )
  {
  sessionID.appendU8( msgBytes.getU8( index ));
  index++;
  }

// "A client which receives a
// legacy_session_id_echo field that does
// not match what it sent in the
// ClientHello MUST abort the handshake with an
// illegal_parameter alert."

tlsMain.setSessionIDLegacy( sessionID );

// It doesn't send the length for the cipher.
Uint8 cipherHigh = msgBytes.getU8( index );
index++;
Uint8 cipherLow = msgBytes.getU8( index );
index++;

StIO::printF( "cipherHigh: " );
StIO::printFUD( cipherHigh );
StIO::putLF();

StIO::printF( "cipherLow: " );
StIO::printFUD( cipherLow );
StIO::putLF();

// 0x13 is decimal 19.
if( !((cipherHigh == 0x13) &&
      (cipherLow == 0x01)))
  {
  // The only cipher this is ready to use now.
  // TLS_AES_128_GCM_SHA256
  throw "cipher can't be used.";
  // StIO::putS( "cipher can't be used." );
  // return Alerts::DecodeError;
  }


  // The hash that is shown in something like
  // TLS_AES_128_GCM_SHA256 is used in the Key
  // Derivation function.

  // This is the only cipher I have working now.
  // "A TLS-compliant application MUST implement
  // TLS_AES_128_GCM_SHA256"

  // See RFC 8446 Appendix B for these
  // ciphersuites.
  // This is a list of AEAD algorithms, and the
  // hash for HKDF, that the client wants to use.
  // TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
  // TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
  // TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
  // TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
  // TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |



Uint8 compressionLength = msgBytes.getU8( index );
index++;

if( compressionLength != 0 )
  {
  throw "ServerHello compression length not zero.";

  // Uint8 compressionValue = msgBytes.getU8( index );
  // index++;

  //  return Alerts::IllegalParameter;
    //}
  }


// Now for the extensions.

StIO::printF( "index for extension is: " );
StIO::printFD( index );
StIO::putLF();

ExtenList extList;
Uint32 result = extList.setFromMsg(
                         msgBytes,
                         index,
                         tlsMain,
                         true, // isServerMsg
                         encryptTls );

StIO::putS( "\nAfter extensions.\n" );

return result;

}
catch( const char* in )
  {
  StIO::putS(
      "Exception in ServerHello.parseBuffer.\n" );
  StIO::putS( in );
  return Alerts::DecodeError;
  }

catch( ... )
  {
  StIO::putS(
       "Exception in ServerHello.parseBuffer." );
  return Alerts::DecodeError;
  }
}



void ServerHello::makeHelloBuf(
                       CharBuf& outBuf,
                       TlsMain& tlsMain,
                       EncryptTls& encryptTls )
{
StIO::putS( "Top of ServerHello.makeHelloBuf." );

CharBuf randBytes;
Randomish::makeRandomBytes( randBytes, 32 + 10 );

for( Int32 count = 0; count < 32; count++ )
  outBuf.appendU8( randBytes.getU8( count ));

// Echo back the session ID that the client sent.
CharBuf sessionID;
tlsMain.getSessionIDLegacy( sessionID );

Int32 idLength = sessionID.getLast();
// This length should have been checked
// when it received the ClientHello.

StIO::printF( "Session ID length: " );
StIO::printFD( idLength );
StIO::putLF();

if( idLength > 32 )
  throw "ServerHello idLength > 32.";

outBuf.appendU8( idLength & 0xFF );

for( Int32 count = 0; count < idLength; count++ )
  outBuf.appendU8( sessionID.getU8( count ));

// Appendix B of RFC 8446 for TLS 1.3 shows
// the cipher suites.

// The server doesn't send the length for
// the cipher.

// TLS_AES_128_GCM_SHA256       | {0x13,0x01} |

outBuf.appendU8( 0x13 );
outBuf.appendU8( 0x01 );

outBuf.appendU8( 0x00 ); // Compression none.

// Extensions go after compression method.


// See RFC 7748 Section 6.1 for what is
// sent here.

Integer k;
CharBuf privKeyBuf;
tlsMain.mCurve.makeRandExponentK( k, privKeyBuf );

Integer U;
U.setFromLong48( 9 );

Integer srvPubKey;
tlsMain.mCurve.montLadder1(
                     srvPubKey, U, k,
                     tlsMain.intMath,
                     tlsMain.mod );

encryptTls.setSrvPrivKey( k );
encryptTls.setSrvPubKey( srvPubKey );

CharBuf extenListBuf;
extenList.makeSrvHelloBuf( extenListBuf,
                           tlsMain,
                           encryptTls );

outBuf.appendCharBuf( extenListBuf );

StIO::putS( "After the extentions." );

Int32 outBufLen = outBuf.getLast();
StIO::printF( "outBufLen: " );
StIO::printFD( outBufLen );
StIO::putLF();
}
