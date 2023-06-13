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

package com.google.solutions.tokenservice.flows;

import io.vertx.core.http.HttpServerRequest;

import javax.enterprise.context.RequestScoped;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MultivaluedMap;

@RequestScoped
public class XlbMtlsClientCredentialsFlow implements AuthenticationFlow {
  public static final String NAME = "xlb-mtls";

  private final HttpServerRequest request;

  public XlbMtlsClientCredentialsFlow(HttpServerRequest request) {
    this.request = request;
  }

  @Override
  public String getGrantType() {
    return null;
  }

  @Override
  public boolean isAvailable() {
    return true;
  }

  @Override
  public TokenResponse authenticate(MultivaluedMap<String, String> parameters) {

    // https://quarkus.io/guides/security-authentication-mechanisms-concept#mutual-tls
    return null;
  }
}
