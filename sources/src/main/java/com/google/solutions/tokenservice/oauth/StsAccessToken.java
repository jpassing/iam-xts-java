package com.google.solutions.tokenservice.oauth;

import java.time.Instant;

/**
 * An OAuth access token for a workload pool identity.
 *
 * @param value encoded token.
 * @param scope scope of value.
 * @param issueTime time of issuance.
 * @param expiryTime time of expiry.
 */
public record StsAccessToken(
  String value,
  String scope,
  Instant issueTime,
  Instant expiryTime
)  implements AccessToken {}