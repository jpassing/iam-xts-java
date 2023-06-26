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
import com.google.api.services.iamcredentials.v1.IAMCredentials;
import com.google.api.services.iamcredentials.v1.model.GenerateAccessTokenRequest;
import com.google.api.services.sts.v1.CloudSecurityToken;
import com.google.api.services.sts.v1.model.GoogleIdentityStsV1ExchangeTokenRequest;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.common.base.Preconditions;
import com.google.solutions.tokenservice.ApplicationVersion;
import com.google.solutions.tokenservice.URLHelper;
import com.google.solutions.tokenservice.UserId;
import com.google.solutions.tokenservice.oauth.AccessToken;
import com.google.solutions.tokenservice.oauth.IdToken;

import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.sql.Date;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

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

  private CloudSecurityToken createStsClient() throws IOException
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

  private IAMCredentials createIamCredentialsClient(AccessToken token) throws IOException
  {
    var credential = GoogleCredentials
      .newBuilder()
      .setAccessToken(
        new com.google.auth.oauth2.AccessToken(token.value(), Date.from(token.expiryTime())))
      .build();

    try {
      return new IAMCredentials
        .Builder(
          HttpTransport.newTransport(),
          new GsonFactory(),
          new HttpCredentialsAdapter(credential))
        .setApplicationName(ApplicationVersion.USER_AGENT)
        .build();
    }
    catch (GeneralSecurityException e) {
      throw new IOException("Creating a IAMCredentials client failed", e);
    }
  }

  /**
   * Exchange an ID token for an STS access token.
   */
  public AccessToken issueAccessToken(
    IdToken idToken,
    String scope
  ) throws IOException {
    Preconditions.checkNotNull(idToken, "idToken");
    Preconditions.checkNotNull(scope, "scope");

    try {
      var client = createStsClient();
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

  /**
   * Impersonate the service account and obtain an access token.
   *
   * @param scopes requested scopes, fully qualified.
   * @param lifetime lifetime of requested token
   */
  public AccessToken impersonateServiceAccount(
    AccessToken accessToken,
    UserId serviceAccount,
    List<String> scopes,
    Duration lifetime
  ) throws AccessException, IOException {
    try {
      var request = new GenerateAccessTokenRequest()
        .setScope(scopes)
        .setLifetime(lifetime.toSeconds() + "s");

      var issueTime = Instant.now();
      var response = createIamCredentialsClient(accessToken)
        .projects()
        .serviceAccounts()
        .generateAccessToken(
          String.format("projects/-/serviceAccounts/%s", serviceAccount.email()),
          request)
        .execute();

      return new AccessToken(
        response.getAccessToken(),
        String.join(" ", scopes),
        issueTime,
        Instant.parse(response.getExpireTime()));
    }
    catch (GoogleJsonResponseException e) {
      switch (e.getStatusCode()) {
        case 401:
          throw new NotAuthenticatedException("Not authenticated", e);
        case 403:
          throw new AccessDeniedException(
            String.format(
              "Denied access to service account '%s': %s",
              serviceAccount.email(),
              e.getMessage()),
            e);
        default:
          throw (GoogleJsonResponseException)e.fillInStackTrace();
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
