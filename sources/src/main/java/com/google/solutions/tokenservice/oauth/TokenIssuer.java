package com.google.solutions.tokenservice.oauth;

import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.common.base.Preconditions;
import com.google.solutions.tokenservice.platform.AccessException;
import com.google.solutions.tokenservice.platform.ServiceAccount;

import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

@ApplicationScoped
public class TokenIssuer {
  private final Options options;
  private final ServiceAccount serviceAccount;

  public TokenIssuer(
    Options options,
    ServiceAccount serviceAccount
  ) {
    Preconditions.checkNotNull(serviceAccount, "serviceAccount");
    Preconditions.checkNotNull(options, "options");
    Preconditions.checkArgument(!options.tokenExiry.isNegative());

    this.options = options;
    this.serviceAccount = serviceAccount;
  }

  public ServiceAccount getServiceAccount() {
    return serviceAccount;
  }

  public TokenWithExpiry issueToken(
    JsonWebToken.Payload payload
  ) throws AccessException, IOException {
    Preconditions.checkNotNull(payload, "payload");

    //
    // Add obligatory claims.
    //
    var iat = Instant.now();
    var expiryTime = iat.plus(this.options.tokenExiry);
    var jwtPayload = payload
      .setAudience(this.serviceAccount.id().toString())
      .setIssuer(this.serviceAccount.id().toString())
      .setIssuedAtTimeSeconds(iat.getEpochSecond())
      .setExpirationTimeSeconds(expiryTime.getEpochSecond());

    // TODO: Add flow, pairwise-sub?

    return new TokenWithExpiry(
      this.serviceAccount.signJwt(jwtPayload),
      expiryTime);
  }

  // -------------------------------------------------------------------------
  // Inner classes.
  // -------------------------------------------------------------------------

  public record TokenWithExpiry(
    String token,
    Instant expiryTime
  ) {}

  public record Options(
    Duration tokenExiry
  ) {}
}
