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

package com.google.solutions.tokenservice.web;

import com.google.solutions.tokenservice.URLHelper;
import com.google.solutions.tokenservice.oauth.IdTokenIssuer;
import com.google.solutions.tokenservice.platform.IntegrationTestEnvironment;
import com.google.solutions.tokenservice.platform.LogAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.enterprise.inject.Instance;
import java.net.URL;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestOAuthResource {

  private static final URL ISSUER_ID = URLHelper.fromString("http://example.com/");

  private OAuthResource resource;

  @BeforeEach
  public void before() {
    this.resource = new OAuthResource();
    this.resource.logAdapter = new LogAdapter();
    this.resource.runtimeEnvironment = Mockito.mock(RuntimeEnvironment.class);
    this.resource.tokenIssuer = new IdTokenIssuer(
      new IdTokenIssuer.Options(ISSUER_ID, null, Duration.ofMinutes(5)),
      IntegrationTestEnvironment.SERVICE_ACCOUNT);
    this.resource.flows = Mockito.mock(Instance.class);
  }

  // -------------------------------------------------------------------------
  // invalid.
  // -------------------------------------------------------------------------

  @Test
  public void whenPathNotMapped_ThenGetReturnsError() throws Exception {
    var response = new RestDispatcher<>(this.resource)
      .get("/api/unknown", OAuthResource.TokenErrorResponse.class);

    assertEquals(404, response.getStatus());
  }

  // -------------------------------------------------------------------------
  // Metadata.
  // -------------------------------------------------------------------------

  @Test
  public void getMetadata() throws Exception {
    var response = new RestDispatcher<>(this.resource)
      .get("/.well-known/openid-configuration", OAuthResource.ProviderMetadata.class);

    assertEquals(200, response.getStatus());

    assertEquals(ISSUER_ID, response.getBody().issuerEndpoint());
    assertEquals(new URL(ISSUER_ID, "/token"), response.getBody().tokenEndpoint());
    assertEquals(new URL(ISSUER_ID, "/token"), response.getBody().authorizationEndpoint());
  }

  // -------------------------------------------------------------------------
  // Token.
  // -------------------------------------------------------------------------

  @Test
  public void whenGrantTypeMissing_thenTokenReturnsError() throws Exception {
    var response = new RestDispatcher<>(this.resource)
      .postForm("/token", Map.ofEntries(), OAuthResource.TokenErrorResponse.class);

    assertEquals(400, response.getStatus());
    assertEquals("invalid_request", response.getBody().error());
  }

  @Test
  public void whenGrantTypeNotSupported_thenTokenReturnsError() throws Exception {
    var response = new RestDispatcher<>(this.resource)
      .postForm("/token", Map.ofEntries(), OAuthResource.TokenErrorResponse.class);

    assertEquals(400, response.getStatus());
    assertEquals("invalid_request", response.getBody().error());
  }

  @Test
  public void whenContentTypeWrong_thenTokenReturnsError() throws Exception {
    var response = new RestDispatcher<>(this.resource)
      .post("/token", OAuthResource.TokenErrorResponse.class);

    assertEquals(415, response.getStatus());
  }
}