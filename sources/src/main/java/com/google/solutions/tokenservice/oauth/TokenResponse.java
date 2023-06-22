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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.solutions.tokenservice.oauth.client.AuthorizedClient;

/**
 * Token response as defined in RFC6749.
 *
 * @param client OAuth client for which the token is being issued
 * @param accessToken REQUIRED. The access token issued by the authorization server.
 * @param accessTokenType REQUIRED. The type of the token issued, case-insensitive.
 * @param accessTokenExpiryInSeconds REQUIRED. The lifetime in seconds of the access token.
 * @param accessTokenScope Scope of the issued security token.
 * @param idToken ID Token.
 */
public record TokenResponse(
  @JsonIgnore
  AuthorizedClient client,

  @JsonIgnore
  IdToken idToken,

  @JsonIgnore
  AccessToken accessToken

) {

  @JsonProperty("id_token")
  public String idTokenValue() {
    return this.idToken.value();
  }

  @JsonProperty("access_token")
  public String accessTokenValue() {
    return this.accessToken == null
      ? null
      : this.accessToken.value();
  }

  @JsonProperty("token_type")
  public String accessTokenType() {
    return this.accessToken == null
      ? null
      : "Bearer";
  }

  @JsonProperty("expires_in")
  public Long accessTokenExpiryInSeconds() {
    return this.accessToken == null
      ? null
      : this.accessToken.expiryTime().getEpochSecond()
        - this.accessToken.issueTime().getEpochSecond();
  }

  @JsonProperty("scope")
  public String accessTokenScope() {
    return this.accessToken == null
      ? null
      : this.accessToken.scope();
  }
}