package com.google.solutions.tokenservice.oauth.client;

import java.time.Instant;
import java.util.Map;

/**
 * An authenticated client.
 *
 * @param clientId OAuth client ID
 * @param authenticationTime time of authentication
 * @param additionalClaims claims about this client
 */
public record AuthenticatedClient(
  String clientId,
  Instant authenticationTime,
  Map<String, String> additionalClaims
) {
}
