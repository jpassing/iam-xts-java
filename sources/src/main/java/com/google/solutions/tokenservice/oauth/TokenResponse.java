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

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Token response as defined in RFC6749.
 *
 * @param accessToken REQUIRED. The access token issued by the authorization server.
 * @param tokenType REQUIRED. The type of the token issued, case-insensitive.
 * @param expiresIn REQUIRED. The lifetime in seconds of the access token.
 * @param scope Scope of the issued security token.
 * @param idToken ID Token.
 */
public record TokenResponse(
  @JsonProperty("access_token")
  String accessToken,

  @JsonProperty("token_type")
  String tokenType,

  @JsonProperty("expires_in")
  int expiresIn,

  @JsonProperty("scope")
  String scope,

  @JsonProperty("id_token")
  String idToken
) {
}