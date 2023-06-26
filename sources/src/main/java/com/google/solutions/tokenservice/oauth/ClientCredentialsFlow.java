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
import com.google.api.client.util.GenericData;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.solutions.tokenservice.UserId;
import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.platform.AccessException;
import com.google.solutions.tokenservice.platform.LogAdapter;
import com.google.solutions.tokenservice.platform.ServiceAccount;
import com.google.solutions.tokenservice.platform.WorkloadIdentityPool;
import com.google.solutions.tokenservice.web.LogEvents;

import java.io.IOException;
import java.time.Instant;

/**
 * Flow for authenticating clients.
 */
public abstract class ClientCredentialsFlow implements AuthenticationFlow {
  private final TokenIssuer issuer;
  private final WorkloadIdentityPool workloadIdentityPool;
  protected final LogAdapter logAdapter;

  public ClientCredentialsFlow(
    TokenIssuer issuer,
    WorkloadIdentityPool workloadIdentityPool,
    LogAdapter logAdapter
  ) {
    this.issuer = issuer;
    this.workloadIdentityPool = workloadIdentityPool;
    this.logAdapter = logAdapter;
  }

  /**
   * Identify and authenticate the client.
   */
  protected abstract AuthenticatedClient authenticateClient(
    AuthenticationRequest request
  );

  /**
   * Issue an ID token for an authenticated client.
   */
  protected IdToken issueIdToken(
    AuthenticatedClient client
  ) throws AccessException, IOException {
    Preconditions.checkNotNull(client, "client");

    //
    // In addition to the standard iss/exp/nbf claims, we
    // include the following claims:
    //
    // - amr: the name of the flow.
    // - aud: audience(s) that this ID Token is intended for. It MUST contain the
    //        OAuth 2.0 client_id of the relying party as an audience value.
    // - client: JSON object containing claims about the client.
    //
    // NB. Because this is a client-credentials flow, we don't set a 'sub' claim.
    //

    var idTokenPayload = new JsonWebToken.Payload()
      .set("amr", name().toLowerCase())
      .set("client_id", client.clientId());

    var clientClaims = new GenericData();
    clientClaims.putAll(client.additionalClaims());
    idTokenPayload.put("client", clientClaims);

    return this.issuer.issueIdToken(
      client,
      idTokenPayload);
  }

  /**
   * Issue an access token. This can be a Google STS token or a
   * Google service account access token.
   */
  protected AccessToken issueAccessToken(
    AuthenticationRequest request,
    AuthenticatedClient client,
    IdToken idToken
  )  throws AccessException, IOException {
    Preconditions.checkNotNull(request, "request");
    Preconditions.checkNotNull(client, "client");
    Preconditions.checkNotNull(idToken, "idToken");

    var scope = request.parameters().getFirst("scope");
    if (Strings.isNullOrEmpty(scope)) {
      //
      // No scope specified, so we don't need to issue an
      // access token.
      //
      return null;
    }

    //
    // Use the ID token to request an access token from the
    // workload identity pool.
    //
    var accessToken = this.workloadIdentityPool.issueAccessToken(idToken, scope);

    return accessToken;
//    var serviceAccountEmail = request.parameters().getFirst("service_account");
//    if (!Strings.isNullOrEmpty(serviceAccountEmail) &&
//        serviceAccountEmail.contains("@")) {
//
//      //
//      // Use STS token to impersonate a service account.
//      //
//      // )
//      //
//      // No impersonation requested, just return the STS token.
//      //
//      return stsToken;
//    }
//    else {
//
//      //TODO: Impersonate a service account.
//      var serviceAccountToken = new AccessToken("todo", "scope", Instant.now(), Instant.now());
//
//      return serviceAccountToken;
//    }
  }

  //---------------------------------------------------------------------------
  // AuthenticationFlow.
  //---------------------------------------------------------------------------

  @Override
  public String grantType() {
    return "client_credentials";
  }

  @Override
  public boolean canAuthenticate(AuthenticationRequest request) {
    Preconditions.checkNotNull(request, "request");

    //
    // Check if the client provided a client_id. Subclasses
    // may perform additional checks.
    //
    if (Strings.isNullOrEmpty(request.parameters().getFirst("client_id"))) {
      this.logAdapter
        .newWarningEntry(
          LogEvents.API_TOKEN,
          "The request lacks a required parameter: client_id")
        .write();
      return false;
    }

    return true;
  }

  @Override
  public final Authentication authenticate(
    AuthenticationRequest request
  ) throws Authentication.AuthenticationException {
    Preconditions.checkNotNull(request, "request");

    //
    // Authenticate the client.
    //
    AuthenticatedClient client;
    try
    {
      client = authenticateClient(request);
    }
    catch (Exception e) {
      throw new Authentication.InvalidClientException(
        "The client or its credentials are invalid", e);
    }

    //
    // Issue tokens.
    //
    IdToken idToken;
    try {
      idToken = issueIdToken(client);
    }
    catch (Exception e) {
      throw new Authentication.TokenIssuanceException(
        String.format("Issuing ID token for client '%s' failed", client.clientId()),
        e);
    }

    try {
      var accessToken = issueAccessToken(request, client, idToken);

      if (accessToken != null) {
        this.logAdapter
          .newInfoEntry(
            LogEvents.API_TOKEN,
            String.format(
              "Issued ID token and access token for client '%s' (scope: %s)",
              client.clientId(),
              accessToken.scope()))
          .write();
      }
      else {
        this.logAdapter
          .newInfoEntry(
            LogEvents.API_TOKEN,
            String.format("Issued ID token for client '%s'", client.clientId()))
          .write();
      }

      return new Authentication(client, idToken, accessToken);
    }
    catch (Exception e) {
      throw new Authentication.TokenIssuanceException(
        String.format("Issuing access token for client '%s' failed", client.clientId()),
        e);
    }
  }
}
