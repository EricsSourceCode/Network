/*
This got merged in to EncryptTls.

// Copyright Eric Chauvin 2023 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



// See https://ericinarizona.github.io/
// For guides and information.


#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppInt/IntegerMath.h"
#include "../CppInt/Mod.h"
#include "../CryptoBase/Sha256.h"
#include "TlsMain.h"

// RFC 5869
// RFC 7748
// RFC 8448


// The cipher suite used in the TLS 1.3
// handshake protocol.
// TLS_AES_128_GCM_SHA256    {0x13,0x01}



class KeyDerive
  {
  private:
  bool testForCopy = false;
  Sha256 sha256;
  CharBuf extractSecretMaster;

  public:
  KeyDerive( void )
    {
    }

  KeyDerive( const KeyDerive& in )
    {
    if( in.testForCopy )
      return;

    throw "KeyDerive copy constructor called.";
    }

  ~KeyDerive( void )
    {
    }

  void setDiffHelmOnClient( TlsMain& tlsMain,
                            Integer& sharedS );

  void setDiffHelmOnServer( TlsMain& tlsMain,
                            Integer& sharedS );

  void setHandshakeKeys(
                     TlsMain& tlsMain,
                     Integer& sharedS,
                     EncryptTls& encryptTls );

  void setAppDataKeys( TlsMain& tlsMain );

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

  };

*/
