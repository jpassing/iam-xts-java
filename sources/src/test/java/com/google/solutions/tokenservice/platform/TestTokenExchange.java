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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestTokenExchange {

  private static final String CLOUD_PLATFORM_SCOPE
    = "https://www.googleapis.com/auth/cloud-platform";

  // -------------------------------------------------------------------------
  // exchangeIdTokenForAccessToken.
  // -------------------------------------------------------------------------

  @Test
  public void whenAudienceInvalid_thenExchangeIdTokenForAccessTokenThrowsException()
    throws Exception {
    var sts = new TokenExchange();

    assertThrows(
      IllegalArgumentException.class,
      () -> sts.exchangeIdTokenForAccessToken(
        "id-token",
        "//invalid-audience",
        CLOUD_PLATFORM_SCOPE));
  }

  @Test
  public void whenTokenInvalid_thenExchangeIdTokenForAccessTokenThrowsException()
    throws Exception {

    assertTrue(false);
  }

  @Test
  public void whenScopeInvalid_thenExchangeIdTokenForAccessTokenThrowsException()
    throws Exception {

    assertTrue(false);
  }
}
