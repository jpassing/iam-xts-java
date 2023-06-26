//
// Copyright 2023 Google LLC
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//

package com.google.solutions.tokenservice.oauth;

import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.common.base.Preconditions;
import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.platform.ApiException;

import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Issuer for ID tokens.
 *
 * To avoid having to manage a dedicated signing key pair, the class uses
 * a service account and its Google-managed key pair to sign tokens.
 */
@ApplicationScoped
public class IdTokenIssuer {
  private final Options options;
  private final ServiceAccount serviceAccount;

  public IdTokenIssuer(
    Options options,
    ServiceAccount serviceAccount
  ) {
    Preconditions.checkNotNull(serviceAccount, "serviceAccount");
    Preconditions.checkNotNull(options, "options");
    Preconditions.checkArgument(!options.tokenExiry.isNegative());

    this.options = options;
    this.serviceAccount = serviceAccount;
  }

  /**
   * @return public URL to JWKS that can be used to verify tokens.
   */
  public URL jwksUrl() {
    return serviceAccount.jwksUrl();
  }

  /**
   * @return OIDC-compliant issuer ID.
   */
  public URL id() {
    return this.options.id();
  }

  /**
   * Issue a signed ID token.
   *
   * @param client
   * @param payload extra claims
   * @return signed token
   */
  public IdToken issueIdToken(
    AuthenticatedClient client,
    JsonWebToken.Payload payload
  ) throws ApiException, IOException {
    Preconditions.checkNotNull(client, "client");
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
    var issueTime = Instant.now();
    var expiryTime = issueTime.plus(this.options.tokenExiry);

    var audience = this.options.tokenAudience != null
      ? this.options.tokenAudience.toString()
      : client.clientId();

    var issuer = this.options.id().toString();
    if (issuer.endsWith("/")) {
      issuer = issuer.substring(0, issuer.length() - 1);
    }

    var jwtPayload = payload
      .setIssuer(issuer)
      .setIssuedAtTimeSeconds(issueTime.getEpochSecond())
      .setAudience(audience)
      .setExpirationTimeSeconds(expiryTime.getEpochSecond())
      .setJwtId(UUID.randomUUID().toString());

    return new IdToken(
      this.serviceAccount.signJwt(jwtPayload),
      issueTime,
      expiryTime);
  }

  // -------------------------------------------------------------------------
  // Inner classes.
  // -------------------------------------------------------------------------

  public record Options(
    URL id,
    URL tokenAudience,
    Duration tokenExiry
  ) {}
}
