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

package com.google.solutions.tokenservice.oauth.mtls;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.solutions.tokenservice.oauth.AuthenticationRequest;
import com.google.solutions.tokenservice.oauth.ClientCredentialsFlow;
import com.google.solutions.tokenservice.oauth.IdTokenIssuer;
import com.google.solutions.tokenservice.oauth.WorkloadIdentityPool;
import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.oauth.client.ClientPolicy;
import com.google.solutions.tokenservice.platform.LogAdapter;
import com.google.solutions.tokenservice.web.LogEvents;

/**
 * Flow that authenticates clients using mTLS.
 *
 * Based on RFC8705 (OAuth 2.0 Mutual-TLS Client Authentication
 * and Certificate-Bound Access Tokens).
 */
public abstract class MtlsClientCredentialsFlow extends ClientCredentialsFlow {

  protected final ClientPolicy clientPolicy;

  public MtlsClientCredentialsFlow(
    ClientPolicy clientPolicy,
    IdTokenIssuer issuer,
    WorkloadIdentityPool workloadIdentityPool,
    LogAdapter logAdapter
  ) {
    super(issuer, workloadIdentityPool, logAdapter);
    this.clientPolicy = clientPolicy;
  }

  /**
   * Extract mTLS client certificate information, and verify its authenticity.
   */
  protected abstract MtlsClientCertificate verifyClientCertificate(
    AuthenticationRequest request
  );

  //---------------------------------------------------------------------------
  // Overrides.
  //---------------------------------------------------------------------------

  @Override
  public String authenticationMethod() {
    return "tls_client_auth";
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
  protected AuthenticatedClient authenticateClient(AuthenticationRequest request) {
    var clientId = request.parameters().getFirst("client_id");

    Preconditions.checkArgument(!Strings.isNullOrEmpty(clientId), "client_id is required");

    //
    // Authenticate the client based on the attributes we've gathered.
    //
    var clientAttributes = verifyClientCertificate(request);
    return this.clientPolicy.authenticateClient(clientId, clientAttributes);
  }
}
