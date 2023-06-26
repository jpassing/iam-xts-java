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

import com.google.solutions.tokenservice.oauth.IdToken;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TestWorkloadIdentityPool {

  private static final String CLOUD_PLATFORM_SCOPE
    = "https://www.googleapis.com/auth/cloud-platform";

  // -------------------------------------------------------------------------
  // IssueAccessToken.
  // -------------------------------------------------------------------------

  @Test
  public void whenPoolInvalid_thenIssueAccessTokenThrowsException()
    throws Exception {

    var options = new WorkloadIdentityPool.Options(
      1,
      "doesnotexist",
      "doesnotexist");

    var sts = new WorkloadIdentityPool(options);

    assertThrows(
      IllegalArgumentException.class,
      () -> sts.issueAccessToken(
        new IdToken("id-token", Instant.now(), Instant.MAX),
        CLOUD_PLATFORM_SCOPE));
  }
}
