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

package com.google.solutions.tokenservice.platform;

import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.sts.v1.CloudSecurityToken;
import com.google.api.services.sts.v1.model.GoogleIdentityStsV1ExchangeTokenRequest;
import com.google.common.base.Preconditions;
import com.google.solutions.tokenservice.ApplicationVersion;
import com.google.solutions.tokenservice.ProjectId;
import com.google.solutions.tokenservice.URLHelper;
import com.google.solutions.tokenservice.oauth.AccessToken;
import com.google.solutions.tokenservice.oauth.IdToken;
import com.google.solutions.tokenservice.oauth.TokenIssuer;

import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;

/**
 * Adapter class for interacting with the STS API.
 */
@ApplicationScoped
public class WorkloadIdentityPool {
  private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
  private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
  private static final String ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";

  private final Options options;

  public WorkloadIdentityPool(Options options) {
    this.options = options;
  }

  private CloudSecurityToken createClient() throws IOException
  {
    try {
      return new CloudSecurityToken
        .Builder(
          HttpTransport.newTransport(),
          new GsonFactory(),
          httpRequest -> {})
        .setApplicationName(ApplicationVersion.USER_AGENT)
        .build();
    }
    catch (GeneralSecurityException e) {
      throw new IOException("Creating an STS client failed", e);
    }
  }

  public AccessToken issueAccessToken(
    IdToken idToken,
    String scope
  ) throws IOException {
    Preconditions.checkNotNull(idToken, "idToken");
    Preconditions.checkNotNull(scope, "scope");

    try {
      var client = createClient();
      var request = new GoogleIdentityStsV1ExchangeTokenRequest()
        .setGrantType(GRANT_TYPE)
        .setAudience(this.options.audience())
        .setScope(scope)
        .setRequestedTokenType(ACCESS_TOKEN_TYPE)
        .setSubjectToken(idToken.value())
        .setSubjectTokenType(ID_TOKEN_TYPE);

      var issueTime = Instant.now();

      var response = client
        .v1()
        .token(request)
        .execute();

      return new AccessToken(
        response.getAccessToken(),
        scope,
        issueTime,
        issueTime.plusSeconds(response.getExpiresIn()));
    }
    catch (GoogleJsonResponseException e) {
      switch (e.getStatusCode()) {
        case 400:
          throw new IllegalArgumentException(e.getMessage());

        default:
          throw (GoogleJsonResponseException) e.fillInStackTrace();
      }
    }
  }

  // -------------------------------------------------------------------------
  // Inner classes.
  // -------------------------------------------------------------------------

  public record Options(
    long projectNumber,
    String poolId,
    String providerId
  ) {
    public String audience() {
      return String.format(
        "//iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s/providers/%s",
        this.projectNumber(),
        this.poolId(),
        this.providerId());
    }

    public URL expectedTokenAudience() {
      return URLHelper.fromString("https:" + audience());
    }
  }
}
