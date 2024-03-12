// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#include "TlsMainSrv.h"

#include "../CppBase/StIO.h"



void TlsMainSrv::setTestVecServerCertOnly(
                             CharBuf& outBuf )
{
StIO::putS(
        "Top of setTestVecServerCertOnly()." );

// Certificate (445 octets):

const char* certRecString = "0b 00 01 b9"
   "00 00 01 b5 00 01 b0 30 82 01 ac"
   "30 82 01 15 a0 03 02 01 02 02 01"
   "02 30 0d 06 09 2a 86 48 86 f7 0d"
   "01 01 0b 05 00 30 0e 31 0c 30 0a"
   "06 03 55 04 03 13 03 72 73 61 30"
   "1e 17 0d 31 36 30 37 33 30 30 31"
   "32 33 35 39 5a 17 0d 32 36 30 37"
   "33 30 30 31 32 33 35 39 5a 30 0e"
   "31 0c 30 0a 06 03 55 04 03 13 03"
   "72 73 61 30 81 9f 30 0d 06 09 2a"
   "86 48 86 f7 0d 01 01 01 05 00 03"
   "81 8d 00 30 81 89 02 81 81 00 b4"
   "bb 49 8f 82 79 30 3d 98 08 36 39"
   "9b 36 c6 98 8c 0c 68 de 55 e1 bd"
   "b8 26 d3 90 1a 24 61 ea fd 2d e4"
   "9a 91 d0 15 ab bc 9a 95 13 7a ce"
   "6c 1a f1 9e aa 6a f9 8c 7c ed 43"
   "12 09 98 e1 87 a8 0e e0 cc b0 52"
   "4b 1b 01 8c 3e 0b 63 26 4d 44 9a"
   "6d 38 e2 2a 5f da 43 08 46 74 80"
   "30 53 0e f0 46 1c 8c a9 d9 ef bf"
   "ae 8e a6 d1 d0 3e 2b d1 93 ef f0"
   "ab 9a 80 02 c4 74 28 a6 d3 5a 8d"
   "88 d7 9f 7f 1e 3f 02 03 01 00 01"
   "a3 1a 30 18 30 09 06 03 55 1d 13"
   "04 02 30 00 30 0b 06 03 55 1d 0f"
   "04 04 03 02 05 a0 30 0d 06 09 2a"
   "86 48 86 f7 0d 01 01 0b 05 00 03"
   "81 81 00 85 aa d2 a0 e5 b9 27 6b"
   "90 8c 65 f7 3a 72 67 17 06 18 a5"
   "4c 5f 8a 7b 33 7d 2d f7 a5 94 36"
   "54 17 f2 ea e8 f8 a5 8c 8f 81 72"
   "f9 31 9c f3 6b 7f d6 c5 5b 80 f2"
   "1a 03 01 51 56 72 60 96 fd 33 5e"
   "5e 67 f2 db f1 02 70 2e 60 8c ca"
   "e6 be c1 fc 63 a4 2a 99 be 5c 3e"
   "b7 10 7c 3c 54 e9 b9 eb 2b d5 20"
   "3b 1c 3b 84 e0 a8 b2 f7 59 40 9b"
   "a3 ea c9 d9 1d 40 2d cc 0c c8 f8"
   "96 12 29 ac 91 87 b4 2b 4d e1 00"
   "00";

CharBuf certStrBuf( certRecString );

CharBuf certBuf;
certBuf.setFromHexTo256( certStrBuf );

StIO::putS( "certBuf (only):" );
certBuf.showHex();

outBuf.copy( certBuf );
}



void TlsMainSrv::setTestVecServerHello(
                               CharBuf& outBuf,
                               TlsMain& tlsMain )
{
StIO::putS( "Top of setTestVecServerHello()." );

Integer k;
Integer pubKey;

// Key values from RFC 8448.
// x25519 key pair:

const char* privKeyString =
      "b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56"
      "52 57 8c c8 10 e9 98 01 91 ec 8d 05 83"
      "08 ce a2 16 a2 1e";

const char* pubKeyString =
      "c9 82 88 76 11 20 95 fe 66 76 2b db"
      "f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1"
      "dd 69 b1 b0 4e 75 1f 0f";

CharBuf privKeyStrBuf( privKeyString );

CharBuf privKeyBuf;
privKeyBuf.setFromHexTo256( privKeyStrBuf );

StIO::putS( "privKeyBuf:" );
privKeyBuf.showHex();

ByteArray cAr;
privKeyBuf.copyToCharArray( cAr );

// This clampK has to be done.
tlsMain.mCurve.clampK( cAr );

tlsMain.mCurve.cArrayToInt( cAr, k );


CharBuf pubKeyStrBuf( pubKeyString );

CharBuf pubKeyBuf;
pubKeyBuf.setFromHexTo256( pubKeyStrBuf );

StIO::putS( "pubKeyBuf:" );

pubKeyBuf.showHex();

pubKeyBuf.copyToCharArray( cAr );
tlsMain.mCurve.cArrayToInt( cAr, pubKey );

// Raise 9 to k and see if I get pubkey.

Integer U;
U.setFromLong48( 9 );
Integer pubKeyTest;
tlsMain.mCurve.montLadder1(
                     pubKeyTest, U, k,
                     tlsMain.intMath,
                     tlsMain.mod );

tlsMain.mCurve.uCoordTo32Bytes( pubKeyTest,
                        cAr, tlsMain.mod,
                        tlsMain.intMath );

StIO::putS( "pubKeyTest:" );
CharBuf testBuf;
testBuf.appendCharArray( cAr, 32 );
testBuf.showHex();

if( !pubKey.isEqual( pubKeyTest ))
  throw
    "setTestVecServerHello Test keys not right.";

StIO::putS( "Got the keys right." );

// This is the clamped value.
encryptTls.setSrvPrivKey( k );
encryptTls.setSrvPubKey( pubKey );


// From RFC 8448:

const char* serverHelloMsgString =
    "02 00 00 56 03 03 a6 af 06 a4 12 18 60"
    "dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5"
    "cb 14 34 da c1 55 77 2e d3 e2 69 28 00"
    "13 01 00 00 2e 00 33 00 24 00 1d 00 20"
    "c9 82 88 76 11 20 95 fe 66 76 2b db f7"
    "c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69"
    "b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";


CharBuf hexServerHelloMsgBuf(
                         serverHelloMsgString );

CharBuf msgBuf;
msgBuf.setFromHexTo256( hexServerHelloMsgBuf );

tlsMain.setServerHelloMsg( msgBuf );

// The server Hello message.  This is the
// whole thing with the outer record.

const char* serverHelloRecString =
      "16 03 03 00 5a 02 00 00 56 03 03 a6"
      "af 06 a4 12 18 60 dc 5e 6e 60 24 9c"
      "d3 4c 95 93 0c 8a c5 cb 14 34 da c1"
      "55 77 2e d3 e2 69 28 00 13 01 00 00"
      "2e 00 33 00 24 00 1d 00 20 c9 82 88"
      "76 11 20 95 fe 66 76 2b db f7 c6 72"
      "e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1"
      "b0 4e 75 1f 0f 00 2b 00 02 03 04";

CharBuf hexBuf( serverHelloRecString );

CharBuf recordBuf;
recordBuf.setFromHexTo256( hexBuf );

StIO::putS( "recordBuf:" );

recordBuf.showHex();

StIO::putS( "End of recordBuf." );

outBuf.copy( recordBuf );
}




Int32 TlsMainSrv::processIncoming(
                        const CharBuf& recvBuf,
                        TlsMain& tlsMain )
{
const Int32 recvLast = recvBuf.getLast();

StIO::printF(
      "TlsMainSrv::processIncoming bytes: " );
StIO::printFD( recvLast );
StIO::putLF();

if( recvLast > 0 )
  {
  // It received some new data.
  for( Int32 count = 0; count < recvLast; count++ )
    circBufIn.addU8( recvBuf.getU8( count ));

  }

const Int32 max = circBufIn.getSize();
for( Int32 count = 0; count < max; count++ )
  {
  if( circBufIn.isEmpty())
    break;

  Uint8 aByte = circBufIn.getU8();
  Uint32 accumResult = tlsOuterRead.
                            accumByte( aByte );
  if( accumResult == Results::Continue )
    continue; // Get more bytes.

  if( accumResult < Results::AlertTop )
    {
    StIO::putS( "tlsOuterRead.accumByte error." );
    sendPlainAlert( accumResult & 0xFF );
    tlsOuterRead.clear();
    // Cause it to time out with read closed.
    return 0;
    }

  if( accumResult == Results::Done )
    {
    recordBytes.clear();
    tlsOuterRead.copyBytes( recordBytes );
    Int32 recBytesLast = recordBytes.getLast();
    StIO::printF( "recordBytes last: " );
    StIO::printFD( recBytesLast );
    StIO::putLF();

    Uint8 recType = tlsOuterRead.getRecordType();
    tlsOuterRead.clear();

    if( recType == TlsOuterRec::Handshake )
      {
      return processHandshake(
                     recordBytes, tlsMain );
      }

    if( recType == TlsOuterRec::ChangeCipherSpec )
      {
      // Ignore this.
      // See sendChangeCipherSpec() for
      // notes about this message.

      StIO::putS( "Got a ChangeCipherSpec." );
      return 1;
      }

    if( recType == TlsOuterRec::Alert )
      {
      // An alert is the alert type, then
      // legacy version, then length for 2 bytes,
      // and it's always a length of 2.
      // Then the level and then description.
      // So get those 6 more bytes next.

      StIO::putS( "Got an Alert." );
      return 1;
      }

    if( recType == TlsOuterRec::ApplicationData )
      {
      StIO::putS( "Got ApplicationData." );

      Int32 appBytesLast = recordBytes.getLast();
      StIO::printF( "appBytes last: " );
      StIO::printFD( appBytesLast );
      StIO::putLF();

      // RFC 8446 Section 5.2
      // Record Payload Protection

      // RFC 8446 Section 5.3.
      // Set the per-record nonce.

      // recordBytes is everything except
      // the 5 starting bytes.
      // The five bytes are:
      // 23, 3, 3, recordBytes.getLast()

      // recordBytes contains this:
      // struct {
      //  opaque content[TLSPlaintext.length];
      //  ContentType type;
      //   uint8 zeros[length_of_padding];
      // } TLSInnerPlaintext;


      CharBuf plainBuf;
      encryptTls.clWriteDecryptCharBuf(
                  recordBytes,
                  plainBuf );

      return processAppData( plainBuf, tlsMain );
      }

    //  RFC 6520
    if( recType == TlsOuterRec::HeartBeat )
      {
      StIO::putS( "Got a HeartBeat." );
      return 1;
      }

    // It didn't find any matching type.
    sendPlainAlert( Alerts::UnexpectedMessage );
    return 0;
    }
  }

return 1;
}



Int32 TlsMainSrv::processHandshake(
                     const CharBuf& inBuf,
                     TlsMain& tlsMain )
{
StIO::putS( "processHandshake" );

CharBuf inBufOnce;
inBufOnce.copy( inBuf );

// Loop and get all messages.
for( Int32 count = 0; count < 100; count++ )
  {
  Uint8 msgID = 0;

  Uint32 hResult = handshakeSrv.processInBuf(
                                inBufOnce,
                                tlsMain,
                                msgID,
                                encryptTls );

  // Clear it after the first one because
  // it has already put it in its own
  // circleBuf.

  inBufOnce.clear();

  if( hResult < Results::AlertTop )
    {
    StIO::putS( "Handshake processInbuf error." );
    sendPlainAlert( hResult & 0xFF );
    // Cause it to time out with read closed.
    return 0;
    }

  if( hResult == Results::Continue )
    return 1;

  if( hResult == Results::Done )
    {
    StIO::putS(
             "Handshake processInbuf Done." );

    StIO::printF( "msgID: " );
    StIO::printFUD( msgID );
    StIO::putLF();

    if( tlsMain.getLastHandshakeID() >= msgID )
      {
      StIO::putS(
           "Handshake message out of order." );
      // Which alert is this?
      sendPlainAlert(
                  Alerts::UnexpectedMessage );
      return 0;
      }

    if( msgID == Handshake::ClientHelloID )
      {
      StIO::putS( "Got a ClientHello." );
      StIO::putS( "Sending ServerHello." );

      tlsMain.setLastHandshakeID(
                 Handshake::ServerHelloID );

      CharBuf outBuf;

      /*
      CharBuf srvHelloBuf;
      handshakeSrv.makeSrvHelloBuf(
                             srvHelloBuf,
                             tlsMain );

      // Int32 toSend = TlsOuterRec::
      TlsOuterRec::
           makeHandshakeRec( srvHelloBuf,
                             outBuf, tlsMain );

      // ServerHello will fit in this unless
      // it is a really small max fragment size.

      */

      setTestVecServerHello( outBuf, tlsMain );
      outgoingBuf.appendCharBuf( outBuf );

      // For compatibility.
      sendChangeCipherSpec();

      Integer sharedS;
      encryptTls.setDiffHelmOnServer(
                         tlsMain, sharedS );

      encryptTls.setHandshakeKeys(
                        tlsMain, sharedS );

      outBuf.clear();

      setTestVecServerCertOuter( outBuf );
      outgoingBuf.appendCharBuf( outBuf );

      outBuf.clear();
      setTestVecServerEncExten( outBuf );
      tlsMain.setEncExtenMsg( outBuf );

      outBuf.clear();
      setTestVecServerCertOnly( outBuf );
      tlsMain.setCertificateMsg( outBuf );

      outBuf.clear();
      setTestVecServerCertVerify( outBuf );
      tlsMain.setCertVerifyMsg( outBuf );

      CharBuf finished;
      encryptTls.makeSrvFinishedMsg( tlsMain,
                                     finished );

      outBuf.clear();
      setTestVecServerFinished( outBuf );
      tlsMain.setSrvWriteFinishedMsg( outBuf );
      continue;
      }

/*
  static const Uint8 NewSessionTicketID = 4;
  static const Uint8 EndOfEarlyDataID = 5;
  static const Uint8 EncryptedExtensionsID = 8;
  static const Uint8 CertificateID = 11;
  static const Uint8 CertificateRequestID = 13;
  static const Uint8 CertificateVerifyID = 15;
*/


    if( msgID == Handshake::FinishedID )
      {
      StIO::putS(
              "Got a Finished Message.\n\n\n" );

      encryptTls.setAppDataKeys( tlsMain );

      CharBuf ticketBuf;
      setTestVecNewSessionTicket( ticketBuf );

      outgoingBuf.appendCharBuf( ticketBuf );
      continue;
      }

/*
  static const Uint8 CertificateUrlRESERVED = 21;
  static const Uint8
                 CertificateStatusRESERVED = 22;
  static const Uint8
                 SupplementalDataRESERVED = 23;
  static const Uint8 KeyUpdateID = 24;
  static const Uint8 MessageHashID = 254;
*/


    if( msgID == Handshake::KeyUpdateID )
      {
      StIO::putS( "Got a KeyUpdateID." );
      tlsMain.setLastHandshakeID(
             Handshake::KeyUpdateID );
      continue;
      }

    if( msgID == Handshake::MessageHashID )
      {
      StIO::putS( "Got a MessageHashID." );
      tlsMain.setLastHandshakeID(
             Handshake::MessageHashID );
      continue;
      }
    }

  StIO::putS( "Handshake message unknown." );
  return -1;
  }

// If someone put over 100 handshake messages
// in to one outer record.

StIO::putS( "It should never loop 100 times." );
return -1;
}



Int32 TlsMainSrv::processAppData(
                     const CharBuf& plainText,
                     TlsMain& tlsMain )
{
StIO::putS( "App data plainText:" );
plainText.showHex();

CharBuf messages;
messages.copy( plainText );

Int32 paddingLast = 0;
const Int32 max = plainText.getLast();

if( max == 0 )
  {
  StIO::putS(
       "processAppData messages was empty." );
  return 0;
  }

for( Int32 count = max - 1; count >= 0; count-- )
  {
  Uint8 aByte = plainText.getU8( count );
  if( aByte != 0 )
    {
    paddingLast = count + 1;
    break;
    }
  }

if( paddingLast == 0 )
  {
  StIO::putS(
     "processAppData Message was all padding." );
  return 0;
  }

messages.truncateLast( paddingLast );

StIO::putS( "messages:" );
messages.showHex();

Int32 messageType = messages.getU8(
                           paddingLast - 1 );

messages.truncateLast( paddingLast - 1 );

// ChangeCipherSpec = 20;
// Alert = 21;
// Handshake = 22;
// ApplicationData = 23;
// HeartBeat = 24;

if( messageType == TlsOuterRec::Handshake )
  {
  StIO::putLF();
  StIO::putS(
      "App data messageType is handshake." );
  StIO::putLF();

  return processHandshake( messages, tlsMain );
  }

if( messageType == TlsOuterRec::ChangeCipherSpec )
  {
  StIO::putS(
           "messageType is ChangeCipherSpec." );

  // What alert do I send back?
  return 0;
  }

if( messageType == TlsOuterRec::Alert )
  {
  StIO::putS( "messageType is Alert." );
  return 1;
  }

if( messageType == TlsOuterRec::ApplicationData )
  {
  StIO::putS(
     "App data messageType is ApplicationData." );
  return 1;
  }

if( messageType == TlsOuterRec::HeartBeat )
  {
  StIO::putS( "messageType is HeartBeat." );
  return 1;
  }

StIO::putS( "messageType is unknown." );
// Send an alert?
return -1;
}


void TlsMainSrv::sendChangeCipherSpec( void )
{
// This is obsolete for TLS 1.3, but it does
// have to be sent for compatibility.
// Like middlebox compatibility.
// Just ignore it if it is being received.

StIO::putS( "Sending ChangeCipherSpec." );

outgoingBuf.appendU8(
              TlsOuterRec::ChangeCipherSpec );

// Legacy version:
outgoingBuf.appendU8( 3 );
outgoingBuf.appendU8( 3 );

// Length:
outgoingBuf.appendU8( 0 );
outgoingBuf.appendU8( 1 );

// A byte that never gets used.
outgoingBuf.appendU8( 1 );
}



void TlsMainSrv::sendPlainAlert(
                           const Uint8 descript )
{
// An alert sent in Plain Text.

// ======
// This has to be sent as an encrypted
// record sometimes.

// Pretend the parameter is being used.
if( descript == 0xFF )
  StIO::printF( "Parameter is being used." );
else
  throw "Send plain alert needs work.";


/*
StIO::printF( "Sending Alert: " );
StIO::printFUD( descript );
StIO::putLF();

const Uint8 level = Alerts::getMatchingLevel(
                                     descript );

// Alerts are in RFC 8446, Section 6.

outgoingBuf.appendU8( TlsOuterRec::Alert );

// Legacy version:
outgoingBuf.appendU8( 3 );
outgoingBuf.appendU8( 3 );

// Length:
outgoingBuf.appendU8( 0 );
outgoingBuf.appendU8( 2 );

outgoingBuf.appendU8( level );
outgoingBuf.appendU8( descript );
*/
}



void TlsMainSrv::copyOutBuf( CharBuf& sendOutBuf )
{
sendOutBuf.copy( outgoingBuf );
outgoingBuf.clear();
}




void TlsMainSrv::setTestVecServerEncExten(
                             CharBuf& outBuf )
{
StIO::putS( "Top of setTestVecServerEncExten()." );


const char* recString = "08 00 00 24"
         "00 22 00 0a 00 14 00"
         "12 00 1d 00 17 00 18"
         "00 19 01 00 01 01 01"
         "02 01 03 01 04 00 1c"
         "00 02 40 01 00 00 00 00";

CharBuf recStrBuf( recString );

CharBuf encExtenBuf;
encExtenBuf.setFromHexTo256( recStrBuf );

StIO::putS( "encExtenBuf:" );
encExtenBuf.showHex();

outBuf.copy( encExtenBuf );
}



void TlsMainSrv::setTestVecServerCertVerify(
                             CharBuf& outBuf )
{
StIO::putS(
    "Top of setTestVecServerCertVerify()." );

const char* recString = "0f 00 00 84"
      "08 04 00 80 5a 74 7c"
      "5d 88 fa 9b d2 e5 5a b0"
      "85 a6 10 15 b7 21 1f 82"
      "4c d4 84 14 5a b3 ff 52"
      "f1 fd a8 47 7b 0b 7a bc"
      "90 db 78 e2 d3 3a 5c 14"
      "1a 07 86 53 fa 6b ef 78"
      "0c 5e a2 48 ee aa a7 85"
      "c4 f3 94 ca b6 d3 0b be"
      "8d 48 59 ee 51 1f 60 29"
      "57 b1 54 11 ac 02 76 71"
      "45 9e 46 44 5c 9e a5 8c"
      "18 1e 81 8e 95 b8 c3 fb"
      "0b f3 27 84 09 d3 be 15"
      "2a 3d a5 04 3e 06 3d da"
      "65 cd f5 ae a2 0d 53 df"
      "ac d4 2f 74 f3";

CharBuf recStrBuf( recString );

CharBuf certVerifyBuf;
certVerifyBuf.setFromHexTo256( recStrBuf );

StIO::putS( "certVerifyBuf:" );
certVerifyBuf.showHex();

outBuf.copy( certVerifyBuf );
}




void TlsMainSrv::setTestVecServerFinished(
                             CharBuf& outBuf )
{
StIO::putS(
    "Top of setTestVecServerFinished()." );

const char* recString = "14 00 00 20"
        "9b 9b 14 1d 90 63 37 fb d2 cb"
        "dc e7 1d f4 de da 4a b4 2c 30"
        "95 72 cb 7f ff ee 54 54 b7 8f"
        "07 18";

CharBuf recStrBuf( recString );

CharBuf finishedBuf;
finishedBuf.setFromHexTo256( recStrBuf );

StIO::putS( "finishedBuf:" );
finishedBuf.showHex();

outBuf.copy( finishedBuf );
}




void TlsMainSrv::setTestVecServerCertOuter(
                             CharBuf& outBuf )
{
StIO::putS(
    "Top of setTestVecServerCertOuter()." );

const char* recString = "17 03 03"
     "02 a2 d1 ff 33 4a 56 f5 bf f6 59"
     "4a 07 cc 87 b5 80 23 3f 50 0f 45"
     "e4 89 e7 f3 3a f3 5e df 78 69 fc"
     "f4 0a a4 0a a2 b8 ea 73 f8 48 a7"
     "ca 07 61 2e f9 f9 45 cb 96 0b 40"
     "68 90 51 23 ea 78 b1 11 b4 29 ba"
     "91 91 cd 05 d2 a3 89 28 0f 52 61"
     "34 aa dc 7f c7 8c 4b 72 9d f8 28"
     "b5 ec f7 b1 3b d9 ae fb 0e 57 f2"
     "71 58 5b 8e a9 bb 35 5c 7c 79 02"
     "07 16 cf b9 b1 18 3e f3 ab 20 e3"
     "7d 57 a6 b9 d7 47 76 09 ae e6 e1"
     "22 a4 cf 51 42 73 25 25 0c 7d 0e"
     "50 92 89 44 4c 9b 3a 64 8f 1d 71"
     "03 5d 2e d6 5b 0e 3c dd 0c ba e8"
     "bf 2d 0b 22 78 12 cb b3 60 98 72"
     "55 cc 74 41 10 c4 53 ba a4 fc d6"
     "10 92 8d 80 98 10 e4 b7 ed 1a 8f"
     "d9 91 f0 6a a6 24 82 04 79 7e 36"
     "a6 a7 3b 70 a2 55 9c 09 ea d6 86"
     "94 5b a2 46 ab 66 e5 ed d8 04 4b"
     "4c 6d e3 fc f2 a8 94 41 ac 66 27"
     "2f d8 fb 33 0e f8 19 05 79 b3 68"
     "45 96 c9 60 bd 59 6e ea 52 0a 56"
     "a8 d6 50 f5 63 aa d2 74 09 96 0d"
     "ca 63 d3 e6 88 61 1e a5 e2 2f 44"
     "15 cf 95 38 d5 1a 20 0c 27 03 42"
     "72 96 8a 26 4e d6 54 0c 84 83 8d"
     "89 f7 2c 24 46 1a ad 6d 26 f5 9e"
     "ca ba 9a cb bb 31 7b 66 d9 02 f4"
     "f2 92 a3 6a c1 b6 39 c6 37 ce 34"
     "31 17 b6 59 62 22 45 31 7b 49 ee"
     "da 0c 62 58 f1 00 d7 d9 61 ff b1"
     "38 64 7e 92 ea 33 0f ae ea 6d fa"
     "31 c7 a8 4d c3 bd 7e 1b 7a 6c 71"
     "78 af 36 87 90 18 e3 f2 52 10 7f"
     "24 3d 24 3d c7 33 9d 56 84 c8 b0"
     "37 8b f3 02 44 da 8c 87 c8 43 f5"
     "e5 6e b4 c5 e8 28 0a 2b 48 05 2c"
     "f9 3b 16 49 9a 66 db 7c ca 71 e4"
     "59 94 26 f7 d4 61 e6 6f 99 88 2b"
     "d8 9f c5 08 00 be cc a6 2d 6c 74"
     "11 6d bd 29 72 fd a1 fa 80 f8 5d"
     "f8 81 ed be 5a 37 66 89 36 b3 35"
     "58 3b 59 91 86 dc 5c 69 18 a3 96"
     "fa 48 a1 81 d6 b6 fa 4f 9d 62 d5"
     "13 af bb 99 2f 2b 99 2f 67 f8 af"
     "e6 7f 76 91 3f a3 88 cb 56 30 c8"
     "ca 01 e0 c6 5d 11 c6 6a 1e 2a c4"
     "c8 59 77 b7 c7 a6 99 9b bf 10 dc"
     "35 ae 69 f5 51 56 14 63 6c 0b 9b"
     "68 c1 9e d2 e3 1c 0b 3b 66 76 30"
     "38 eb ba 42 f3 b3 8e dc 03 99 f3"
     "a9 f2 3f aa 63 97 8c 31 7f c9 fa"
     "66 a7 3f 60 f0 50 4d e9 3b 5b 84"
     "5e 27 55 92 c1 23 35 ee 34 0b bc"
     "4f dd d5 02 78 40 16 e4 b3 be 7e"
     "f0 4d da 49 f4 b4 40 a3 0c b5 d2"
     "af 93 98 28 fd 4a e3 79 4e 44 f9"
     "4d f5 a6 31 ed e4 2c 17 19 bf da"
     "bf 02 53 fe 51 75 be 89 8e 75 0e"
     "dc 53 37 0d 2b";

CharBuf recStrBuf( recString );

CharBuf certOuterBuf;
certOuterBuf.setFromHexTo256( recStrBuf );

StIO::putS( "certOuterBuf:" );
certOuterBuf.showHex();
StIO::putLF();

outBuf.copy( certOuterBuf );
}



void TlsMainSrv::setTestVecNewSessionTicket(
                             CharBuf& outBuf )
{
StIO::putS(
  "\n\n\nTop of setTestVecNewSessionTicket()." );

const char* recString = "17 03 03 00 de 3a"
         "6b 8f 90 41 4a 97 d6 95 9c 34 87"
         "68 0d e5 13 4a 2b 24 0e 6c ff ac"
         "11 6e 95 d4 1d 6a f8 f6 b5 80 dc"
         "f3 d1 1d 63 c7 58 db 28 9a 01 59"
         "40 25 2f 55 71 3e 06 1d c1 3e 07"
         "88 91 a3 8e fb cf 57 53 ad 8e f1"
         "70 ad 3c 73 53 d1 6d 9d a7 73 b9"
         "ca 7f 2b 9f a1 b6 c0 d4 a3 d0 3f"
         "75 e0 9c 30 ba 1e 62 97 2a c4 6f"
         "75 f7 b9 81 be 63 43 9b 29 99 ce"
         "13 06 46 15 13 98 91 d5 e4 c5 b4"
         "06 f1 6e 3f c1 81 a7 7c a4 75 84"
         "00 25 db 2f 0a 77 f8 1b 5a b0 5b"
         "94 c0 13 46 75 5f 69 23 2c 86 51"
         "9d 86 cb ee ac 87 aa c3 47 d1 43"
         "f9 60 5d 64 f6 50 db 4d 02 3e 70"
         "e9 52 ca 49 fe 51 37 12 1c 74 bc"
         "26 97 68 7e 24 87 46 d6 df 35 30"
         "05 f3 bc e1 86 96 12 9c 81 53 55"
         "6b 3b 6c 67 79 b3 7b f1 59 85 68"
         "4f";

CharBuf recStrBuf( recString );

CharBuf ticketBuf;
ticketBuf.setFromHexTo256( recStrBuf );

StIO::putS( "ticketBuf:" );
ticketBuf.showHex();

outBuf.copy( ticketBuf );
}
