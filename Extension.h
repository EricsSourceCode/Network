// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#pragma once



#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "EncryptTls.h"
#include "TlsMain.h"



// Specific extensions are in different RFCs.



class Extension
  {
  private:
  bool testForCopy = false;

  public:
  inline Extension( void )
    {
    }

  inline Extension( const Extension& in )
    {
    if( in.testForCopy )
      return;

    throw "Extension copy constructor called.";
    }

  inline ~Extension( void )
    {
    }

  Uint32 serverName( const CharBuf& data,
                     TlsMain& tlsMain );

  Uint32 supportedVersions( const CharBuf& data,
                            TlsMain& tlsMain,
                            bool isServerMsg );

  Uint32 signatureAlgorithms( const CharBuf& data,
                              TlsMain& tlsMain );

  Uint32 signatureAlgorithmsCert(
                            const CharBuf& data,
                            TlsMain& tlsMain );

  Uint32 sessionTicket( void );

  Uint32 supportedGroups( const CharBuf& data,
                          TlsMain& tlsMain );

  Uint32 keyShare( const CharBuf& data,
                   TlsMain& tlsMain,
                   bool isServerMsg,
                   EncryptTls& encryptTls );

  };
