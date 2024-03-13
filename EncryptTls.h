// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



// For information and guides see:
// https://ericssourcecode.github.io/



#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppInt/IntegerMath.h"
#include "../CryptoBase/AesGalois.h"
#include "../CryptoBase/MCurve.h"
#include "../CppInt/Mod.h"
#include "../CryptoBase/Sha256.h"
#include "TlsMain.h"




class EncryptTls
  {
  private:
  bool testForCopy = false;
  Sha256 sha256;
  CharBuf extractSecretMaster;
  Uint64 clWriteRecSequence = 0;
  Uint64 srvWriteRecSequence = 0;
  CharBuf staticClWriteIV;
  CharBuf staticSrvWriteIV;
  MCurve mCurve;
  Integer clientPrivKey; // X25519 32 bytes
  Integer clientPubKey;
  Integer servPrivKey;
  Integer servPubKey;
  AesGalois aesClientWrite;
  AesGalois aesServerWrite;
  CharBuf clHsTraffic;
  CharBuf srvHsTraffic;


  void extract( CharBuf& prk,
                const CharBuf& salt,
                const CharBuf& ikm );

  void expand( CharBuf& T1,
               // CharBuf& T2,
               // CharBuf& T3,
               const CharBuf& prk,
               const CharBuf& info );
               // const Int32 L );

  void hkdfExpandLabel( CharBuf& outBuf,
                        const CharBuf& secret,
                        const CharBuf& label,
                        const CharBuf& context,
                        const Int32 length );

  void deriveSecret( CharBuf& outBuf,
                     const CharBuf& secret,
                     const CharBuf& label,
                     const CharBuf& messages );

  inline Uint64 getClWriteRecSequence( void )
    {
    return clWriteRecSequence;
    }

  inline void incrementClWriteRecSequence( void )
    {
    clWriteRecSequence++;
    }

  inline void setClWriteRecSequenceZero( void )
    {
    clWriteRecSequence = 0;
    }

  inline Uint64 getSrvWriteRecSequence( void )
    {
    return srvWriteRecSequence;
    }

  inline void incrementSrvWriteRecSequence( void )
    {
    srvWriteRecSequence++;
    }

  inline void setSrvWriteRecSequenceZero( void )
    {
    srvWriteRecSequence = 0;
    }


  public:
  EncryptTls( void )
    {
    // aesServerWrite.encryptTest();
    }

  EncryptTls( const EncryptTls& in )
    {
    if( in.testForCopy )
      return;

    throw "EncryptTls copy constructor.";
    }

  ~EncryptTls( void )
    {
    }


  void setDiffHelmOnClient( TlsMain& tlsMain,
                            Integer& sharedS );

  void setDiffHelmOnServer( TlsMain& tlsMain,
                            Integer& sharedS );

  void setHandshakeKeys(
                     TlsMain& tlsMain,
                     Integer& sharedS );

  void setAppDataKeys( TlsMain& tlsMain );

  void setClientPubKey( const Integer& toSet )
    {
    clientPubKey.copy( toSet );
    }

  void getClientPubKey( Integer& toGet ) const
    {
    toGet.copy( clientPubKey );
    }

  void setClientPrivKey(
                        const Integer& toSet )
    {
    clientPrivKey.copy( toSet );
    }

  void getClientPrivKey( Integer& toGet ) const
    {
    toGet.copy( clientPrivKey );
    }

  void setSrvPubKey( const Integer& toSet )
    {
    servPubKey.copy( toSet );
    }

  void getSrvPubKey( Integer& toGet ) const
    {
    toGet.copy( servPubKey );
    }

  void setSrvPrivKey( const Integer& toSet )
    {
    servPrivKey.copy( toSet );
    }

  void getSrvPrivKey( Integer& toGet ) const
    {
    toGet.copy( servPrivKey );
    }

  void setStaticClWriteIV( const CharBuf& toSet )
    {
    staticClWriteIV.copy( toSet );
    }

  void getStaticClWriteIV(
                        CharBuf& toGet ) const
    {
    toGet.copy( staticClWriteIV );
    }


  void setStaticSrvWriteIV(
                       const CharBuf& toSet )
    {
    staticSrvWriteIV.copy( toSet );
    }


  void getStaticSrvWriteIV(
                       CharBuf& toGet ) const
    {
    toGet.copy( staticSrvWriteIV );
    }

/*
  void srvWriteEncryptCharBuf(
                       const CharBuf& plainBuf,
                       CharBuf& cipherBuf );
*/

  void srvWriteDecryptCharBuf(
                     const CharBuf& cipherBuf,
                     CharBuf& plainBuf );

/*
  void clWriteEncryptCharBuf(
                       const CharBuf& plainBuf,
                       CharBuf& cipherBuf );
*/

  void clWriteDecryptCharBuf(
                     const CharBuf& cipherBuf,
                     CharBuf& plainBuf );

  void makeSrvFinishedMsg( TlsMain& tlsMain,
                          CharBuf& finished );

  void makeClFinishedMsg( TlsMain& tlsMain,
                          CharBuf& finished );

  };
