// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html




#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/CharBuf.h"
#include "../CppBase/CircleBuf.h"
#include "TlsMain.h"
#include "Alerts.h"
#include "Handshake.h"
#include "HandshakeSrv.h"
#include "Results.h"
#include "TlsOuterRec.h"
#include "EncryptTls.h"



class TlsMainSrv
  {
  private:
  bool testForCopy = false;
  CircleBuf circBufIn;
  CharBuf recordBytes;
  CharBuf outgoingBuf;
  TlsOuterRec tlsOuterRead;
  HandshakeSrv handshakeSrv;

  public:
  EncryptTls encryptTls;

  TlsMainSrv( void )
    {
    circBufIn.setSize(
          TlsMain::MaxRecordLengthCipher  * 8 );
    }


  TlsMainSrv( const TlsMainSrv &in )
    {
    if( in.testForCopy )
      return;

    throw "TlsMainSrv copy constructor.";
    }

  ~TlsMainSrv( void )
    {
    }

  void sendPlainAlert( const Uint8 descript );

  void sendChangeCipherSpec( void );

  Int32 processIncoming(
                   const CharBuf& recvBuf,
                   TlsMain& tlsMain );

  Int32 processHandshake(
                     const CharBuf& inBuf,
                     TlsMain& tlsMain );

  Int32 processAppData(
                     const CharBuf& plainText,
                     TlsMain& tlsMain );

  void copyOutBuf( CharBuf& sendOutBuf );
  void setTestVecServerHello( CharBuf& outBuf,
                              TlsMain& tlsMain );

  void setTestVecServerCertOnly(
                         CharBuf& outBuf );
  void setTestVecServerEncExten(
                           CharBuf& outBuf );
  void setTestVecServerCertVerify(
                           CharBuf& outBuf );
  void setTestVecServerFinished(
                           CharBuf& outBuf );
  void setTestVecServerCertOuter(
                           CharBuf& outBuf );
  void setTestVecNewSessionTicket(
                           CharBuf& outBuf );

  };
