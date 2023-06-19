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

import java.net.URL;
import java.util.Collection;

/*
 * OIDC provider metadata as defined in [OIDC.Discovery],
 * section 3.
 *
 * @param issuerEndpoint REQUIRED. This MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.
 * @param authorizationEndpoint REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core].
 * @param tokenEndpoint REQUIRED. URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core].
 * @param jwksEndpoint REQUIRED. URL of the OP's JSON Web Key Set [JWK] document.
 * @param supportedResponseTypes REQUIRED. List of the OAuth 2.0 response_type values
 * @param supportedGrantTypes OPTIONAL. List of the OAuth 2.0 Grant Type values that this OP supports.
 * @param supportedSubjectTypes REQUIRED. List of the Subject Identifier types that this OP supports.
 * @param supportedIdTokenSigningAlgorithms REQUIRED. List of the JWS signing algorithms (alg values) supported
 * @param supportedTokenEndpointAuthenticationMethods OPTIONAL. List of Client Authentication methods
 * supported by this Token Endpoint.
 */
public record ProviderMetadata(
  @JsonProperty("issuer")
  URL issuerEndpoint,

  @JsonProperty("authorization_endpoint")
  URL authorizationEndpoint,

  @JsonProperty("token_endpoint")
  URL tokenEndpoint,

  @JsonProperty("jwks_uri")
  URL jwksEndpoint,

  @JsonProperty("response_types_supported")
  Collection<String> supportedResponseTypes,

  @JsonProperty("grant_types_supported")
  Collection<String> supportedGrantTypes,
  
  @JsonProperty("subject_types_supported")
  Collection<String> supportedSubjectTypes,
  
  @JsonProperty("id_token_signing_alg_values_supported")
  Collection<String> supportedIdTokenSigningAlgorithms,

  @JsonProperty("token_endpoint_auth_methods_supported")
  Collection<String> supportedTokenEndpointAuthenticationMethods
  ) {
}
