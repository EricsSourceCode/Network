// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#pragma once


#include "../CppBase/BasicTypes.h"
#include "SocketsApi.h"
#include "../CppBase/TimeApi.h"


// This is the server's view of one client
// socket.



class SrvClient
  {
  private:
  bool testForCopy = false;
  Int64 timeActive = 0;
  bool allowRead = true;

  protected:
  SrvClient( void );
  SocketCpp mainSocket = SocketsApi::InvalSock;

  public:
  SrvClient( SocketCpp useSocket );
  SrvClient( const SrvClient &in );
  virtual ~SrvClient( void );

  virtual Int32 processData( void );
  inline Int64 getTimeActive( void ) const
    {
    return timeActive;
    }

  inline void setTimeActiveNow( void )
    {
    timeActive = TimeApi::getSecondsNow();
    }

  inline bool isActive( void )
    {
    if( mainSocket == SocketsApi::InvalSock )
      return false;

    Int64 diff = TimeApi::getSecondsNow() -
                 timeActive;

    if( diff < 20 )
      return true;

    return false;
    }

  inline void setAllowReadFalse( void )
    {
    // This is like telling it to close this
    // socket down.  If an alert is sent
    // and then the socket is immediately
    // closed, the socket on the other end
    // might not ever receive the alert
    // message, and the reason it is closing.
    // So this is like saying it is going
    // to close.  Soon.  It will just time
    // out for no activity.

    allowRead = false;
    }


  inline bool getAllowRead( void )
    {
    return allowRead;
    }

  void readSocket( CharBuf& recvBuf );
  Int32 writeSocket( const CharBuf& sendBuf );

  };
