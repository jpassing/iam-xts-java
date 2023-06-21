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

  public IdToken issueToken(
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
    var issueTime = Instant.now();
    var expiryTime = issueTime.plus(this.options.tokenExiry);

    var jwtPayload = payload
      .setIssuer(this.options.id().toString())
      .setAudience(audience)
      .setNotBeforeTimeSeconds(issueTime.getEpochSecond()) // TODO: Add 5min slack
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
    Duration tokenExiry
  ) {}
}
