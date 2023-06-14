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

import com.google.solutions.tokenservice.oauth.ProviderMetadata;
import com.google.solutions.tokenservice.oauth.TokenIssuer;
import com.google.solutions.tokenservice.platform.IntegrationTestEnvironment;
import com.google.solutions.tokenservice.platform.LogAdapter;
import com.google.solutions.tokenservice.oauth.TokenError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.enterprise.inject.Instance;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class TestOAuthResource {
  private OAuthResource resource;

  @BeforeEach
  public void before() {
    this.resource = new OAuthResource();
    this.resource.logAdapter = new LogAdapter();
    this.resource.runtimeEnvironment = Mockito.mock(RuntimeEnvironment.class);
    this.resource.tokenIssuer = new TokenIssuer(IntegrationTestEnvironment.SERVICE_ACCOUNT);
    this.resource.flows = Mockito.mock(Instance.class);

    when(this.resource.runtimeEnvironment.createAbsoluteUriBuilder(any(UriInfo.class)))
      .thenReturn(UriBuilder.fromUri("https://localhost/"));
  }

  // -------------------------------------------------------------------------
  // invalid.
  // -------------------------------------------------------------------------

  @Test
  public void whenPathNotMapped_ThenGetReturnsError() throws Exception {
    var response = new RestDispatcher<>(this.resource)
      .get("/api/unknown", TokenError.class);

    assertEquals(404, response.getStatus());
  }

  // -------------------------------------------------------------------------
  // Metadata.
  // -------------------------------------------------------------------------

  @Test
  public void getMetadata() throws Exception {
    var response = new RestDispatcher<>(this.resource)
      .get("/.well-known/openid-configuration", ProviderMetadata.class);

    assertEquals(200, response.getStatus());

    assertEquals("https://localhost/", response.getBody().issuerEndpoint());
    assertEquals("https://localhost/token", response.getBody().tokenEndpoint());
    assertEquals("https://localhost/token", response.getBody().authorizationEndpoint());
  }

  // -------------------------------------------------------------------------
  // Token.
  // -------------------------------------------------------------------------

  @Test
  public void whenGrantTypeMissing_thenTokenReturnsError() throws Exception {
    var response = new RestDispatcher<>(this.resource)
      .postForm("/token", Map.ofEntries(), TokenError.class);

    assertEquals(400, response.getStatus());
    assertEquals("invalid_request", response.getBody().error());
  }

  @Test
  public void whenGrantTypeNotSupported_thenTokenReturnsError() throws Exception {
    var response = new RestDispatcher<>(this.resource)
      .postForm("/token", Map.ofEntries(), TokenError.class);

    assertEquals(400, response.getStatus());
    assertEquals("invalid_request", response.getBody().error());
  }

  @Test
  public void whenContentTypeWrong_thenTokenReturnsError() throws Exception {
    var response = new RestDispatcher<>(this.resource)
      .post("/token", TokenError.class);

    assertEquals(415, response.getStatus());
  }
}