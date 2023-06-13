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

import com.google.solutions.tokenservice.adapters.LogAdapter;
import com.google.solutions.tokenservice.UserId;
import com.google.solutions.tokenservice.oauth.TokenError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.time.Duration;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class TestApiResource {
  private static final UserId SAMPLE_USER = new UserId("user-1@example.com");
  private static final UserId SAMPLE_USER_2 = new UserId("user-2@example.com");

  private static final String SAMPLE_TOKEN = "eySAMPLE";
  private static final Pattern DEFAULT_JUSTIFICATION_PATTERN = Pattern.compile("pattern");
  private static final int DEFAULT_MIN_NUMBER_OF_REVIEWERS = 1;
  private static final int DEFAULT_MAX_NUMBER_OF_REVIEWERS = 10;
  private static final String DEFAULT_HINT = "hint";
  private static final Duration DEFAULT_ACTIVATION_DURATION = Duration.ofMinutes(5);

  private OAuthResource resource;

  @BeforeEach
  public void before() {
    this.resource = new OAuthResource();
    this.resource.logAdapter = new LogAdapter();
    this.resource.runtimeEnvironment = Mockito.mock(RuntimeEnvironment.class);

    when(this.resource.runtimeEnvironment.createAbsoluteUriBuilder(any(UriInfo.class)))
      .thenReturn(UriBuilder.fromUri("https://localhost/"));
  }

  // -------------------------------------------------------------------------
  // getPolicy.
  // -------------------------------------------------------------------------

  @Test
  public void whenPathNotMapped_ThenGetReturnsError() throws Exception {
    var response = new RestDispatcher<>(this.resource, SAMPLE_USER)
      .get("/api/unknown", TokenError.class);

    assertEquals(404, response.getStatus());
  }
}