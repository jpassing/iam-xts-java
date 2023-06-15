package com.google.solutions.tokenservice.oauth;

import java.time.OffsetDateTime;

/**
 * Client attributes conveyed in the client certificate.
 *
 * @param spiffeId SPIFFE ID of the certificate
 * @param sanDns dNSName SAN entry in the certificate
 * @param sanUri uniformResourceIdentifier SAN entry in the certificate
 * @param fingerprint SHA-256 fingerprint of the client certificate
 * @param serialNumber  serial number of the client certificate
 * @param notBefore timestamp before which the client certificate is not valid.
 * @param notAfter timestamp after which the client certificate is not valid.
 */
public record MtlsClientCertificate(
  String spiffeId,
  String sanDns,
  String sanUri,
  String fingerprint,
  String serialNumber,
  OffsetDateTime notBefore,
  OffsetDateTime notAfter
){
}
