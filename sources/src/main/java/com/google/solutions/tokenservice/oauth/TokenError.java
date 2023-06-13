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
 * Token error response entity as defined in RFC6749.
 *
 * @param error Error code
 * @param description Description
 */
public record TokenError(
  @JsonProperty("error")
  String error,

  @JsonProperty("error_description")
  String description
) {

  public TokenError(String errorCode, Exception exception) {
    this(errorCode, exception.getMessage());
  }

  public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
  public static final String ACCESS_DENIED = "access_denied";
  public static final String INVALID_REQUEST = "invalid_request";
  public static final String SERVER_ERROR = "server_error";
  public static final String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
}
