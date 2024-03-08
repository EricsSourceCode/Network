// Copyright Eric Chauvin 2022 - 2024.



// This is licensed under the GNU General
// Public License (GPL).  It is the
// same license that Linux has.
// https://www.gnu.org/licenses/gpl-3.0.html


#pragma once


#include "../CppBase/BasicTypes.h"
#include "../CppBase/StIO.h"


class Alerts
  {
  private:
  bool testForCopy = false;

  public:
  // Obsolete levels:
  static const Uint8 LevelWarning = 1;
  static const Uint8 LevelFatal = 2;

  static const Uint8 CloseNotify = 0;
  static const Uint8 UnexpectedMessage = 10;
  static const Uint8 BadRecordMac = 20;
  //  decryption_failed_RESERVED(21),
  static const Uint8 RecordOverflow = 22;
  // decompression_failure_RESERVED(30),
  static const Uint8 HandshakeFailure = 40;
  // no_certificate_RESERVED(41),
  static const Uint8 BadCertificate = 42;
  static const Uint8 UnsupportedCertificate = 43;
  static const Uint8 CertificateRevoked = 44;
  static const Uint8 CertificateExpired = 45;
  static const Uint8 CertificateUnknown = 46;
  static const Uint8 IllegalParameter = 47;
  static const Uint8 UnknownCa = 48;
  static const Uint8 AccessDenied = 49;
  static const Uint8 DecodeError = 50;
  static const Uint8 DecryptError = 51;
  // export_restriction_RESERVED(60),
  static const Uint8 ProtocolVersion = 70;
  static const Uint8 InsufficientSecurity = 71;
  static const Uint8 InternalError = 80;
  static const Uint8 InappropriateFallback = 86;
  static const Uint8 UserCanceled = 90;
  // no_renegotiation_RESERVED(100),
  static const Uint8 MissingExtension = 109;
  static const Uint8 UnsupportedExtension = 110;
  // certificate_unobtainable_RESERVED(111),
  static const Uint8 UnrecognizedName = 112;
  static const Uint8
              BadCertificateStatusResponse = 113;
  // bad_certificate_hash_value_RESERVED(114),
  static const Uint8 UnknownPskIdentity = 115;
  static const Uint8 CertificateRequired = 116;
  static const Uint8 NoApplicationProtocol
                                          = 120;


  inline Alerts( void )
    {
    }

  inline Alerts( const Alerts& in )
    {
    if( in.testForCopy )
      return;

    throw "Alerts copy constructor called.";
    }

  inline ~Alerts( void )
    {
    }


  inline static Uint8 getMatchingLevel(
                            const Uint8 descript )
    {
    // The level is obsolete and can be ignored,
    // but it still has to be sent.
    // Also, this function documents how the
    // Alerts should be interpreted.

    if( descript == CloseNotify )
      return LevelWarning;

    if( descript == UserCanceled )
      return LevelWarning;


    // The RFC says: "All the alerts listed in
    // Section 6.2 MUST be sent with
    // AlertLevel=fatal..."

    if( descript == UnexpectedMessage )
      return LevelFatal;

    if( descript == BadRecordMac )
      return LevelFatal;

    if( descript == RecordOverflow )
      return LevelFatal;

    if( descript == HandshakeFailure )
      return LevelFatal;

    if( descript == BadCertificate )
      return LevelFatal;

    if( descript == UnsupportedCertificate )
      return LevelFatal;

    if( descript == CertificateRevoked )
      return LevelFatal;

    if( descript == CertificateExpired )
      return LevelFatal;

    if( descript == CertificateUnknown )
      return LevelFatal;

    if( descript == IllegalParameter )
      return LevelFatal;

    if( descript == UnknownCa )
      return LevelFatal;

    if( descript == AccessDenied )
      return LevelFatal;


    if( descript == DecodeError )
      return LevelFatal;

    if( descript == DecryptError )
      return LevelFatal;

    if( descript == ProtocolVersion )
      return LevelFatal;

    if( descript == InsufficientSecurity )
      return LevelFatal;

    if( descript == InternalError )
      return LevelFatal;

    if( descript == InappropriateFallback )
      return LevelFatal;

    if( descript == MissingExtension )
      return LevelFatal;

    if( descript == UnsupportedExtension )
      return LevelFatal;

    if( descript == UnrecognizedName )
      return LevelFatal;

    if( descript == BadCertificateStatusResponse )
      return LevelFatal;

    if( descript == UnknownPskIdentity )
      return LevelFatal;

    if( descript == CertificateRequired )
      return LevelFatal;

    if( descript == NoApplicationProtocol )
      return LevelFatal;

    // An unknown alert is fatal.
    return LevelFatal;
    }


  inline static void showAlert(
                           const Uint8 descript )
    {
    if( descript == CloseNotify )
      {
      StIO::putS( "Alert is CloseNotify." );
      return;
      }

    if( descript == UserCanceled )
      {
      StIO::putS( "Alert is UserCanceled." );
      return;
      }

    if( descript == UnexpectedMessage )
      {
      StIO::putS( "Alert is UnexpectedMessage." );
      return;
      }

    if( descript == BadRecordMac )
      {
      StIO::putS( "Alert is BadRecordMac." );
      return;
      }

    if( descript == RecordOverflow )
      {
      StIO::putS( "Alert is RecordOverflow." );
      return;
      }

    if( descript == HandshakeFailure )
      {
      StIO::putS( "Alert is HandshakeFailure." );
      return;
      }

    if( descript == BadCertificate )
      {
      StIO::putS( "Alert is BadCertificate." );
      return;
      }

    if( descript == UnsupportedCertificate )
      {
      StIO::putS(
          "Alert is UnsupportedCertificate." );
      return;
      }

    if( descript == CertificateRevoked )
      {
      StIO::putS( "Alert is CertificateRevoked." );
      return;
      }

    if( descript == CertificateExpired )
      {
      StIO::putS( "Alert is CertificateExpired." );
      return;
      }

    if( descript == CertificateUnknown )
      {
      StIO::putS( "Alert is CertificateUnknown." );
      return;
      }

    if( descript == IllegalParameter )
      {
      StIO::putS( "Alert is IllegalParameter." );
      return;
      }

    if( descript == UnknownCa )
      {
      StIO::putS( "Alert is UnknownCa." );
      return;
      }

    if( descript == AccessDenied )
      {
      StIO::putS( "Alert is AccessDenied." );
      return;
      }

    if( descript == DecodeError )
      {
      StIO::putS( "Alert is DecodeError." );
      return;
      }

    if( descript == DecryptError )
      {
      StIO::putS( "Alert is DecryptError." );
      return;
      }

    if( descript == ProtocolVersion )
      {
      StIO::putS( "Alert is ProtocolVersion." );
      return;
      }

    if( descript == InsufficientSecurity )
      {
      StIO::putS( "Alert is InsufficientSecurity." );
      return;
      }

    if( descript == InternalError )
      {
      StIO::putS( "Alert is InternalError." );
      return;
      }

    if( descript == InappropriateFallback )
      {
      StIO::putS(
               "Alert is InappropriateFallback." );
      return;
      }

    if( descript == MissingExtension )
      {
      StIO::putS( "Alert is MissingExtension." );
      return;
      }

    if( descript == UnsupportedExtension )
      {
      StIO::putS(
              "Alert is UnsupportedExtension." );
      return;
      }

    if( descript == UnrecognizedName )
      {
      StIO::putS( "Alert is UnrecognizedName." );
      return;
      }

    if( descript == BadCertificateStatusResponse )
      {
      StIO::putS(
        "Alert is BadCertificateStatusResponse." );
      return;
      }

    if( descript == UnknownPskIdentity )
      {
      StIO::putS( "Alert is UnknownPskIdentity." );
      return;
      }

    if( descript == CertificateRequired )
      {
      StIO::putS( "Alert is CertificateRequired." );
      return;
      }

    if( descript == NoApplicationProtocol )
      {
      StIO::putS(
             "Alert is NoApplicationProtocol." );
      return;
      }

    StIO::printF( "Alert is unknown type: " );
    StIO::printFD( descript );
    StIO::putLF();
    }


  };
