// Copyright Eric Chauvin 2022 - 2024.




// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppInt/IntegerMath.h"
#include "../CppInt/Mod.h"
#include "../CryptoBase/MCurve.h"



class TlsMain
  {
  private:
  bool testForCopy = false;
  CharBuf serverName;
  CharBuf clientRandom;
  CharBuf serverRandom;
  CharBuf sessionIDLegacy;
  bool supportedVersions13 = false;
  Int32 maxFragLength = MaxRecordLength;
  bool hasX25519 = false;
  bool needsWorkDone = false; // place holder.
  Uint8 lastHandshakeID = 0;
  CharBuf clientHelloMsg;
  CharBuf serverHelloMsg;
  CharBuf encExtenMsg;
  CharBuf certificateMsg;
  CharBuf certVerifyMsg;
  CharBuf clWriteFinishedMsg;
  CharBuf srvWriteFinishedMsg;
  CharBuf clHsTraffic;
  CharBuf srvHsTraffic;

  public:
  //  0x8000 is 2^15.
  // 0x10000 is 2^16.
  // 2 to the 14.
  static const Int32 MaxRecordLength = 0x4000;

  // For encrypted records that have things
  // added like Additional Authenticated Data,
  // the maximum AEAD expansion is 255 bytes.
  // The max length is:

  static const Int32 MaxRecordLengthCipher =
                     MaxRecordLength + 256;

  IntegerMath intMath;
  Mod mod;
  MCurve mCurve;

  TlsMain( void )
    {
    StIO::putS( "TlsMain constructor:" );
    mCurve.makeThePrime( intMath );
    }

  TlsMain( const TlsMain& in )
    {
    if( in.testForCopy )
      return;

    throw "TlsMain copy constructor called.";
    }

  ~TlsMain( void )
    {
    }


  void setNeedsWorkDone( bool setTo )
    {
    needsWorkDone = setTo;
    }


  bool getIsVersion13( void ) const
    {
    return supportedVersions13;
    }

  void setVersion13True( void )
    {
    supportedVersions13 = true;
    }

  bool getHasX25519( void ) const
    {
    return hasX25519;
    }

  void setHasX25519True( void )
    {
    hasX25519 = true;
    }

  void setServerName( const CharBuf& toSet )
    {
    serverName.copy( toSet );
    }

  void getServerName( CharBuf& toGet ) const
    {
    toGet.copy( serverName );
    }

  void setSessionIDLegacy( const CharBuf& toSet )
    {
    sessionIDLegacy.copy( toSet );
    }


  void getSessionIDLegacy( CharBuf& toGet )
    {
    toGet.copy( sessionIDLegacy );
    }


  Int32 getMaxFragLength( void )
    {
    return maxFragLength;
    }

  Uint8 getLastHandshakeID( void ) const
    {
    return lastHandshakeID;
    }

  void setLastHandshakeID( Uint8 toSet )
    {
    lastHandshakeID = toSet;
    }

  void setClientRandom( const CharBuf& toSet )
    {
    clientRandom.copy( toSet );
    }

  void getClientRandom( CharBuf& toGet ) const
    {
    toGet.copy( clientRandom );
    }

  void setServerRandom( const CharBuf& toSet )
    {
    serverRandom.copy( toSet );
    }

  void getServerRandom( CharBuf& toGet ) const
    {
    toGet.copy( serverRandom );
    }

  void setClientHelloMsg( const CharBuf& toSet )
    {
    clientHelloMsg.copy( toSet );
    }

  void getClientHelloMsg( CharBuf& toGet ) const
    {
    toGet.copy( clientHelloMsg );
    }

  void setServerHelloMsg( const CharBuf& toSet )
    {
    serverHelloMsg.copy( toSet );
    }

  void getServerHelloMsg( CharBuf& toGet ) const
    {
    toGet.copy( serverHelloMsg );
    }


  void setEncExtenMsg( const CharBuf& toSet )
    {
    encExtenMsg.copy( toSet );
    }

  void getEncExtenMsg( CharBuf& toGet ) const
    {
    toGet.copy( encExtenMsg );
    }


  void setCertificateMsg( const CharBuf& toSet )
    {
    certificateMsg.copy( toSet );
    }

  void getCertificateMsg( CharBuf& toGet ) const
    {
    toGet.copy( certificateMsg );
    }


  void setCertVerifyMsg( const CharBuf& toSet )
    {
    certVerifyMsg.copy( toSet );
    }

  void getCertVerifyMsg( CharBuf& toGet ) const
    {
    toGet.copy( certVerifyMsg );
    }


  void setClWriteFinishedMsg(
                     const CharBuf& toSet )
    {
    clWriteFinishedMsg.copy( toSet );
    }

  void getClWriteFinishedMsg(
                       CharBuf& toGet ) const
    {
    toGet.copy( clWriteFinishedMsg );
    }

  void setSrvWriteFinishedMsg(
                      const CharBuf& toSet )
    {
    srvWriteFinishedMsg.copy( toSet );
    }

  void getSrvWriteFinishedMsg(
                       CharBuf& toGet ) const
    {
    toGet.copy( srvWriteFinishedMsg );
    }


  void getClHsTraffic( CharBuf& toGet ) const
    {
    toGet.copy( clHsTraffic );
    }

  void getSrvHsTraffic( CharBuf& toGet ) const
    {
    toGet.copy( srvHsTraffic );
    }

  void setClHsTraffic( const CharBuf& toSet )
    {
    clHsTraffic.copy( toSet );
    }

  void setSrvHsTraffic( const CharBuf& toSet )
    {
    srvHsTraffic.copy( toSet );
    }



  // RFC 8446 Section 5.3.
  // "Each sequence number is set to zero
  // at the beginning of a connection
  // and whenever the key is changed; the
  // first record transmitted under a
  // particular traffic key MUST use
  // sequence number 0."

  };
