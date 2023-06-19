package com.google.solutions.tokenservice.oauth;

import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.common.base.Preconditions;
import com.google.solutions.tokenservice.platform.AccessException;
import com.google.solutions.tokenservice.platform.ServiceAccount;

import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

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

  public URL jwksUrl() {
    return serviceAccount.jwksUrl();
  }

  public URL id() {
    return this.options.id();
  }

  public TokenWithExpiry issueToken(
    String audience,
    JsonWebToken.Payload payload
  ) throws AccessException, IOException {
    Preconditions.checkNotNull(payload, "payload");

    //
    // Add standard set of JWT claims based on
    // https://datatracker.ietf.org/doc/html/rfc7519#section-4
    //
    // - iss: identifies the principal that issued the JWT.
    // - aud: identifies the recipients that the JWT is intended for.
    // - nbf: identifies the time before which the JWT MUST NOT be accepted for processing.
    // - exp: identifies the expiration time on or after which the JWT
    //        MUST NOT be accepted for processing.
    // - jti: a unique identifier for the JWT.
    //
    var now = Instant.now();
    var expiryTime = now.plus(this.options.tokenExiry);

    var jwtPayload = payload
      .setIssuer(this.options.id().toString())
      .setAudience(audience)
      .setNotBeforeTimeSeconds(now.getEpochSecond())
      .setExpirationTimeSeconds(expiryTime.getEpochSecond())
      .setJwtId(UUID.randomUUID().toString());

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
    URL id,
    Duration tokenExiry
  ) {}
}
