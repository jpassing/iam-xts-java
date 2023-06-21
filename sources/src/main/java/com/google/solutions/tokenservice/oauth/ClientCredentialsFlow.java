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
import com.google.common.base.Strings;
import com.google.solutions.tokenservice.UserId;
import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.oauth.client.ClientPolicy;
import com.google.solutions.tokenservice.platform.AccessException;
import com.google.solutions.tokenservice.platform.LogAdapter;
import com.google.solutions.tokenservice.web.LogEvents;
import io.vertx.codegen.doc.Token;

import javax.ws.rs.ForbiddenException;
import java.io.IOException;
import java.time.Instant;

/**
 * Flow for authenticating clients.
 */
public abstract class ClientCredentialsFlow implements AuthenticationFlow {
  private final String DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

  private final TokenIssuer issuer;
  protected final LogAdapter logAdapter;
  protected final ClientPolicy clientPolicy;

  public ClientCredentialsFlow(
    ClientPolicy clientPolicy,
    TokenIssuer issuer,
    LogAdapter logAdapter
  ) {
    this.clientPolicy = clientPolicy;
    this.issuer = issuer;
    this.logAdapter = logAdapter;
  }

  /**
   * Identify and authenticate the client.
   */
  protected abstract AuthenticatedClient authenticateClient(
    TokenRequest request
  );

  /**
   * Issue an ID token for an authenticated client.
   */
  protected BearerToken issueIdToken(
    AuthenticatedClient client
  ) throws AccessException, IOException {
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

    return this.issuer.issueToken(
      client.clientId(),
      idTokenPayload);
  }

  /**
   * Issue an access token.
   */
  protected BearerToken issueAccessToken(
    TokenRequest request,
    AuthenticatedClient client,
    BearerToken idToken
  ) {
    var provider = request.parameters().getFirst("provider");
    if (Strings.isNullOrEmpty(provider)) {
      //
      // The client did not request an access token.
      //
      return null;
    }

    //
    // Use the ID token and provider to perform an STS token exchange.
    //
    var scope = request.parameters().getFirst("scope");
    if (Strings.isNullOrEmpty(scope)) {
      scope = DEFAULT_SCOPE;
    }

    var stsToken = new BearerToken("todo", Instant.now(), Instant.now());

    var serviceAccount = request.parameters().getFirst("impersonate_service_account");
    if (Strings.isNullOrEmpty(serviceAccount)) {
      //
      // No impersonation requested, just return the STS token.
      //
      return stsToken;
    }
    else {
      //
      // Impersonate a service account.
      //
      var serviceAccountToken =  new BearerToken("todo", Instant.now(), Instant.now());

      return serviceAccountToken;
    }
  }

  /**
   * Issue an STS access token.
   */
  protected BearerToken issueStsToken(
    BearerToken idToken,
    String provider,
    String scope
  ) {
    return null;
  }

  /**
   * Issue an access token for a service account.
   */
  protected BearerToken issueServiceAccountAccessToken(
    BearerToken stsToken,
    UserId serviceAccount
  ) {
    return null;
  }

  //---------------------------------------------------------------------------
  // AuthenticationFlow.
  //---------------------------------------------------------------------------

  @Override
  public String grantType() {
    return "client_credentials";
  }

  @Override
  public boolean canAuthenticate(TokenRequest request) {
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
  public final TokenResponse authenticate(
    TokenRequest request
  ) throws AccessException, IOException {

    //
    // Authenticate the client.
    //
    AuthenticatedClient client;
    try
    {
      client = authenticateClient(request);
    }
    catch (Exception e) {
      throw new ForbiddenException(
        "The client or its credentials are invalid", e);
    }


    var idToken = issueIdToken(client);
    var accessToken = issueAccessToken(request, client, idToken);
    

    var provider = request.parameters().getFirst("provider");

    if (Strings.isNullOrEmpty(provider)) {
      //
      // The client only requested an ID token.
      //

      var idToken = issueIdToken(client);

      return new TokenResponse(
        client,
        idToken.token(),
        null,
        null,
        null,
        null);
    }
    else {
      //
      // The client requested an ID token and an access token.
      //
      var scope = request.parameters().getFirst("scope");
      if (Strings.isNullOrEmpty(scope)) {
        scope = DEFAULT_SCOPE;
      }

      var idToken = issueIdToken(client);
      var accessToken = issueStsToken(
        idToken,
        provider,
        scope);

      var serviceAccount = request.parameters().getFirst("impersonate_service_account");
      if (!Strings.isNullOrEmpty(serviceAccount)) {
        accessToken = issueServiceAccountAccessToken(accessToken, new UserId(serviceAccount));
      }

      return new TokenResponse(
        client,
        idToken.token(),
        accessToken.token(),
        "Bearer",
        accessToken.expiryTime().getEpochSecond() - accessToken.issueTime().getEpochSecond(),
        scope);
    }
  }
}
