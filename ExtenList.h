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


// For the general idea of extensions, see
// RFCs 4366, 6066.

// See RFC 8446 Section 4.2 for Extensions.

// Specific extensions are in different RFCs.
// See Extension.cpp for each different extension.


class ExtenList
  {
  private:
  bool testForCopy = false;


  Uint32 setOneExt( const Uint32 extType,
                    const CharBuf& data,
                    TlsMain& tlsMain,
                    bool isServerMsg,
                    EncryptTls& encryptTls );

  public:
  // RFC 6066:
  static const Uint8 ServerName = 0;
  static const Uint8 MaxFragmentLength = 1;
  // 2 client_certificate_url
  // 3 trusted_ca_keys
  // 4 truncated_hmac
  static const Uint8 StatusRequest = 5;
  // 6 user_mapping
  // 7 client_authz
  // 8 server_authz
  // 9 cert_type

  // RFC 8422, 7919:
  static const Uint8 SupportedGroups = 10;
  // elliptic_curves(10),
  // ec_point_formats(11) obsolete.

  // 12 srp

  // RFC 8446:
  static const Uint8 SignatureAlgorithms = 13;

  // RFC 5764:
  static const Uint8 UseSrtp = 14;

  // RFC 6520:
  static const Uint8 HeartBeat = 15;

  // RFC 7301
  static const Uint8 AppLayerProtocolNegot = 16;

  // 17 status_request_v2

  // RFC 6962
  static const Uint8 SignedCertTimeStamp = 18;

  // RFC 7250
  static const Uint8 ClientCertType = 19;
  static const Uint8 ServerCertType = 20;

  // RFC 7685
  static const Uint8 Padding = 21;

  // 22 encrypt_then_mac

 // RFC 7627
  static const Uint8
           ExtendedMasterSecretReserved = 23;

  // 24 token_binding
  // 25 cached_info
  // 26 tls_lts
  // 27 compress_certificate

  static const Uint8 RecordSizeLimit = 28;

  // 29 pwd_protect
  // 30 pwd_clear
  // 31 password_salt
  // 32 ticket_pinning
  // 33 tls_cert_with_extern_psk
  // 34 delegated_credentials

  static const Uint8 SessionTicketReserved = 35;

  // 36 TLMSP
  // 37 TLMSP_proxying
  // 38 TLMSP_delegate
  // 39 supported_ekt_ciphers
  // 40 Reserved

  // RFC 8446
  static const Uint16 PreSharedKey = 41;
  static const Uint16 EarlyData = 42;
  static const Uint16 SupportedVersions = 43;
  static const Uint16 Cookie = 44;
  static const Uint16 PskKeyExchModes = 45;
  // Reserved 46
  static const Uint16 CertificateAuthorities = 47;
  static const Uint16 OidFilters = 48;
  static const Uint16 PostHandshakeAuth = 49;
  static const Uint16 SignatureAlgCert = 50;
  static const Uint16 KeyShare = 51;

  // 52 transparency_info
  // 53 connection_id
  // 54 connection_id
  // 55 external_id_hash
  // 56 external_session_id
  // 57 quic_transport_parameters
  // 58 ticket_request
  // 59 dnssec_chain
  // 65280 Reserved for Private Use

  static const Uint16
              RenegotiationInfoReserved = 65281;

  // 65282-65535 Reserved for Private Use


  inline ExtenList( void )
    {
    }

  inline ExtenList( const ExtenList& in )
    {
    if( in.testForCopy )
      return;

    throw "ExtenList copy constructor called.";
    }

  inline ~ExtenList( void )
    {
    }


  Uint32 setFromMsg(  const CharBuf& allBytes,
                      const Int32 indexStart,
                      TlsMain& tlsMain,
                      bool isServerMsg,
                      EncryptTls& encryptTls );

  bool makeClHelloBuf( CharBuf& outBuf,
                       TlsMain& tlsMain,
                       EncryptTls& encryptTls );

  bool makeSrvHelloBuf( CharBuf& outBuf,
                        TlsMain& tlsMain,
                        EncryptTls& encryptTls );

  };
