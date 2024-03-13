// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


// For information and guides see:
// https://ericssourcecode.github.io/




#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppBase/CircleBuf.h"
#include "TlsMain.h"
#include "Alerts.h"
#include "Handshake.h"
#include "HandshakeCl.h"
#include "Results.h"
#include "TlsOuterRec.h"
#include "EncryptTls.h"
#include "NetClient.h"



class TlsMainCl
  {
  private:
  bool testForCopy = false;
  TlsMain tlsMain;
  NetClient netClient;
  CircleBuf circBufIn;
  CharBuf recordBytes;
  CharBuf outgoingBuf;
  TlsOuterRec tlsOuterRead;
  HandshakeCl handshakeCl;
  EncryptTls encryptTls;

  public:
  TlsMainCl( void )
    {
    circBufIn.setSize(
         TlsMain::MaxRecordLengthCipher * 8 );
    }


  TlsMainCl( const TlsMainCl &in )
    {
    if( in.testForCopy )
      return;

    throw "TlsMainCl copy constructor.";
    }

  ~TlsMainCl( void )
    {
    }

  void sendPlainAlert( const Uint8 descript );

  Int32 processIncoming( void );

  Int32 processOutgoing( void );

  void copyOutBuf( CharBuf& sendOutBuf );

  Int32 processAppData(
                    const CharBuf& plainText );

  Int32 processHandshake(
                     const CharBuf& inBuf );

  // bool sendTestVecFinished( void );

  bool startTestVecHandshake(
                     const CharBuf& urlDomain,
                     const CharBuf& port );

  bool startHandshake( const CharBuf& urlDomain,
                       const CharBuf& port );


  };
