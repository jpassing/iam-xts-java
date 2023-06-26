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

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.solutions.tokenservice.oauth.client.ClientPolicy;
import com.google.solutions.tokenservice.platform.LogAdapter;
import com.google.solutions.tokenservice.platform.WorkloadIdentityPool;
import com.google.solutions.tokenservice.web.LogEvents;
import io.vertx.core.http.HttpServerRequest;

import javax.enterprise.context.Dependent;
import javax.ws.rs.ForbiddenException;
import java.time.OffsetDateTime;

/**
 * Flow that authenticates clients using mTLS, terminated
 * by an external Google Cloud load balancer (XLB).
 *
 * The XLB verifies the certificate chain against a trusted CA,
 * which corresponds to the "PKI Mutual-TLS Method" described in
 * RFC8705.
 */
@Dependent
public class XlbMtlsClientCredentialsFlow extends MtlsClientCredentialsFlow {
  public static final String NAME = "xlb-mtls-client-credentials";

  private final Options options;
  private final HttpServerRequest request;

  private static OffsetDateTime parseIfNotNull(String date) {
    if (!Strings.isNullOrEmpty(date)) {
      return OffsetDateTime.parse(date);
    }
    else {
      return null;
    }
  }

  public XlbMtlsClientCredentialsFlow(
    Options options,
    ClientPolicy clientRepository,
    TokenIssuer issuer,
    WorkloadIdentityPool workloadIdentityPool,
    HttpServerRequest request,
    LogAdapter logAdapter
  ) {
    super(clientRepository, issuer, workloadIdentityPool, logAdapter);
    this.request = request;
    this.options = options;
  }

  //---------------------------------------------------------------------------
  // Overrides.
  //---------------------------------------------------------------------------

  @Override
  public String name() {
    return NAME;
  }

  @Override
  public boolean canAuthenticate(AuthenticationRequest request) {
    Preconditions.checkNotNull(request, "request");

    var headers = this.request.headers();

    var certPresent = headers.get(this.options.clientCertPresentHeaderName);
    if (Strings.isNullOrEmpty(certPresent))
    {
      this.logAdapter
        .newWarningEntry(
          LogEvents.API_TOKEN,
          String.format(
            "The header %s is missing, verify that mTLS is enabled for the load balancer backend",
            this.options.clientCertPresentHeaderName))
        .write();

      return false;
    }
    else if (!"true".equalsIgnoreCase(certPresent))
    {
      this.logAdapter
        .newWarningEntry(
          LogEvents.API_TOKEN,
          String.format(
            "The request did not include a client certificate (%s: %s)",
            this.options.clientCertPresentHeaderName,
            certPresent))
        .write();

      return false;
    }

    return super.canAuthenticate(request);
  }

  public MtlsClientCertificate verifyClientCertificate(AuthenticationRequest request)
  {
    //
    // Verify that the client presented a certificate and that the
    // load balancer verified the certificate.
    //
    var headers = this.request.headers();
    if (!canAuthenticate(request))
    {
      throw new ForbiddenException(
        "The request did not include a client certificate");
    }

    if (!"true".equalsIgnoreCase(headers.get(this.options.clientCertChainVerifiedHeaderName)))
    {
      this.logAdapter
        .newErrorEntry(
          LogEvents.API_TOKEN,
          String.format(
            "The client certificate did not pass verification: (%s: %s, %s: %s [sha256])",
            this.options.clientCertErrorHeaderName,
            headers.get(this.options.clientCertErrorHeaderName),
            this.options.clientCertHashHeaderName,
            headers.get(this.options.clientCertHashHeaderName)))
        .write();

      throw new ForbiddenException("The client certificate did not pass verification");
    }

    //
    // NB. There's no way for us to check that the "Verified" header was
    // added by the load balancer (as opposed to a MITM or the client),
    // and that the header is authentic. But if the app is deployed correctly
    // (with the correct ingress settings), then bypassing or MITM-ing the
    // load balancer should not be possible.
    //

    //
    // Return all attributes from HTTP headers. Note that some
    // attributes might be empty.
    //
    return new MtlsClientCertificate(
      headers.get(this.options.clientCertSpiffeIdHeaderName),
      headers.get(this.options.clientCertDnsSansHeaderName),
      headers.get(this.options.clientCertUriSansHeaderName),
      headers.get(this.options.clientCertHashHeaderName),
      headers.get(this.options.clientCertSerialNumberHeaderName),
      parseIfNotNull(headers.get(this.options.clientCertNotBeforeHeaderName)),
      parseIfNotNull(headers.get(this.options.clientCertNotAfterHeaderName)));
  }

  // -------------------------------------------------------------------------
  // Inner classes.
  // -------------------------------------------------------------------------

  public record Options(
    String clientCertPresentHeaderName,
    String clientCertChainVerifiedHeaderName,
    String clientCertErrorHeaderName,
    String clientCertSpiffeIdHeaderName,
    String clientCertDnsSansHeaderName,
    String clientCertUriSansHeaderName,
    String clientCertHashHeaderName,
    String clientCertSerialNumberHeaderName,
    String clientCertNotBeforeHeaderName,
    String clientCertNotAfterHeaderName
  ) {}
}
