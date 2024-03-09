// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#pragma once



#include "../CppBase/BasicTypes.h"



class Handshake
  {
  private:
  bool testForCopy = false;

  public:
  // The types of handshake messages.
  // These are in the order they have to be sent.
  static const Uint8 HelloRequestRESERVED = 0;
  static const Uint8 ClientHelloID = 1;
  static const Uint8 ServerHelloID = 2;
  static const Uint8
                 HelloVerifyRequestRESERVED = 3;
  static const Uint8 NewSessionTicketID = 4;
  static const Uint8 EndOfEarlyDataID = 5;
  static const Uint8 HelloRetryRequestRESERVED = 6;
  static const Uint8 EncryptedExtensionsID = 8;
  static const Uint8 CertificateID = 11;
  static const Uint8
                 ServerKeyExchangeRESERVED = 12;
  static const Uint8 CertificateRequestID = 13;
  static const Uint8 ServerHelloDoneRESERVED = 14;
  static const Uint8 CertificateVerifyID = 15;
  static const Uint8
                 ClientKeyExchangeRESERVED = 16;
  static const Uint8 FinishedID = 20;
  static const Uint8 CertificateUrlRESERVED = 21;
  static const Uint8
                 CertificateStatusRESERVED = 22;
  static const Uint8
                 SupplementalDataRESERVED = 23;
  static const Uint8 KeyUpdateID = 24;
  static const Uint8 MessageHashID = 254;


  Handshake( void )
    {
    }

  Handshake( const Handshake& in )
    {
    if( in.testForCopy )
      return;

    throw "Handshake copy constructor called.";
    }

  ~Handshake( void )
    {
    }

  static bool recordTypeGood(
                          const Uint8 theType )
    {
    if( (theType == ClientHelloID) ||
        (theType == ServerHelloID) ||
        (theType == NewSessionTicketID) ||
        (theType == EndOfEarlyDataID) ||
        (theType == EncryptedExtensionsID) ||
        (theType == CertificateID) ||
        (theType == CertificateRequestID) ||
        (theType == CertificateVerifyID) ||
        (theType == FinishedID) ||
        (theType == KeyUpdateID) ||
        (theType == MessageHashID) ||
        // Reserved types from older
        // versions that might be received.
        (theType == HelloRequestRESERVED) // ||

    // (theType == HelloVerifyRequestRESERVED) ||
    // (theType == HelloRetryRequestRESERVED) ||
    // (theType == ServerKeyExchangeRESERVED) ||
    // (theType == ServerHelloDoneRESERVED) ||
    // (theType == ClientKeyExchangeRESERVED) ||
    // (theType == CertificateUrlRESERVED) ||
    // (theType == CertificateStatusRESERVED) ||
    // (theType == SupplementalDataRESERVED )
        )
      return true;

    return false;
    }

  };
