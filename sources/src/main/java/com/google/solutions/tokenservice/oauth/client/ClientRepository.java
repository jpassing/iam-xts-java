package com.google.solutions.tokenservice.oauth.client;

import com.google.solutions.tokenservice.oauth.MtlsClientCertificate;

import javax.enterprise.context.ApplicationScoped;
import java.time.Instant;
import java.util.HashMap;

/**
 * Repository for known clients.
 *
 * This is an example implementation. A real implementation might use
 * an inventory database or configuration file to authenticate clients.
 *
 */
@ApplicationScoped
public class ClientRepository {
  /**
   * Authenticate a client.
   *
   * @param clientId clientId conveyed in request.
   * @param attributes attributes conveyed in client certificate, verified
   * @return Client if successful
   * @throws if the client is unknown of the attributes are invalid
   */
  public AuthenticatedClient authenticateClient(
    String clientId,
    MtlsClientCertificate attributes
  )
  {
    //
    // In a real-world scenario, we'd use an inventory database to check
    // if the client ID exists and whether the presented attributes match
    // what we're expecting.
    //
    // Optionally, we could look up additional client metadata in the inventory
    // and return it as additional claims.
    //
    // In this sample implementation, we consider any client valid and simply
    // echo the input claims.
    //

    var claims = new HashMap<String, String>();
    claims.put("spiffe", attributes.spiffeId());
    claims.put("san_dns", attributes.sanDns());
    claims.put("san_uri", attributes.sanUri());
    claims.put("fingerprint", attributes.fingerprint());
    claims.put("serial", attributes.serialNumber());

    return new AuthenticatedClient(
      clientId,
      Instant.now(),
      claims);
  }
}
