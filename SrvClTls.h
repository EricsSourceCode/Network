// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html



#pragma once



#include "../CppBase/BasicTypes.h"
#include "../CppBase/CircleBuf.h"
#include "SrvClient.h"
#include "TlsMain.h"
#include "TlsMainSrv.h"



class SrvClTls: public SrvClient
  {
  private:
  TlsMain tlsMain;
  TlsMainSrv tlsMainSrv;

  protected:
  SrvClTls( void );

  public:
  SrvClTls( SocketCpp useSocket );
  ~SrvClTls( void ) override;
  Int32 processData( void ) override;

  };
