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

import com.fasterxml.jackson.annotation.JsonProperty;

/** OAuth token response.
 *
 * @param accessToken
 * @param tokenType
 * @param expiresIn
 * @param scope
 * @param idToken
 */
public record TokenResponse(
  String accessToken,
  String tokenType,
  int expiresIn,
  String scope,
  String idToken
) {
  /**
   * REQUIRED. The access token issued by the authorization server.
   */
  @JsonProperty("access_token") // TODO: Merge into ctor?
  public String getAccessToken() {
    return this.accessToken;
  }

  /**
   * REQUIRED. The type of the token issued, case-insensitive.
   */
  @JsonProperty("token_type")
  public String getTokenType() {
    return this.tokenType;
  }

  /**
   * RECOMMENDED. The lifetime in seconds of the access token.  For
   * example, the value "3600" denotes that the access token will
   * expire in one hour from the time the response was generated.
   */
  @JsonProperty("expires_in")
  public int getExpiresIn() {
    return this.expiresIn;
  }

  /**
   * OPTIONAL. Scope of the issued security token. REQUIRED if
   * the scope is not identical to the scope requested by the client.
   */
  @JsonProperty("scope")
  public String getScope() {
    return this.scope;
  }

  /**
   * OPTIONAL. ID Token value associated with the authenticated
   */
  @JsonProperty("id_token")
  public String getIdToken() {
    return this.idToken;
  }
}
