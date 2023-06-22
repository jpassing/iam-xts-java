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

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.solutions.tokenservice.Exceptions;
import com.google.solutions.tokenservice.oauth.*;
import com.google.solutions.tokenservice.platform.LogAdapter;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;

/**
 * REST API controller.
 */
@RequestScoped
@Path("/")
public class OAuthResource {
  @Inject
  RuntimeEnvironment runtimeEnvironment;

  @Inject
  RuntimeConfiguration configuration;

  @Inject
  LogAdapter logAdapter;

  @Inject
  Instance<AuthenticationFlow> flows;

  @Inject
  TokenIssuer tokenIssuer;

  // -------------------------------------------------------------------------
  // REST resources.
  // -------------------------------------------------------------------------

  /**
   * Root endpoint, redirect to OIDC metadata.
   */
  @GET
  @Produces(MediaType.APPLICATION_JSON)
  public Response getRoot() throws URISyntaxException {
    return Response
      .temporaryRedirect(new URI("/.well-known/openid-configuration"))
      .build();
  }

  /**
   * OIDC provider metadata.
   */
  @GET
  @Path(".well-known/openid-configuration")
  @Produces(MediaType.APPLICATION_JSON)
  public ProviderMetadata getMetadata(
    @Context UriInfo uriInfo) throws MalformedURLException {

    var tokenUrl = new URL(this.tokenIssuer.id(), "/token");

    return new ProviderMetadata(
      this.tokenIssuer.id(),
      tokenUrl, // We don't have a real authorization endpoint
      tokenUrl,
      this.tokenIssuer.jwksUrl(),
      List.of("none"),
      this.flows.stream()
        .map(f -> f.grantType())
        .distinct()
        .collect(Collectors.toList()),
      List.of("pairwise"),
      List.of("RS256"),
      this.flows.stream()
        .map(f -> f.authenticationMethod())
        .distinct()
        .collect(Collectors.toList()));
  }

  /**
   * OAuth token endpoint.
   */
  @POST
  @Path("token")
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  public TokenResponse post(
    @Context HttpHeaders headers,
    @FormParam("grant_type") String grantType,
    MultivaluedMap<String, String> parameters
  ) throws Exception {
    if (Strings.isNullOrEmpty(grantType))
    {
      throw new IllegalArgumentException("A grant type is required");
    }

    //
    // Find a flow that:
    // - is enabled (in the configuration)
    // - supports the requested grant type
    // - supports the presented set of request parameters
    //
    var request = new TokenRequest(grantType, parameters);
    var flow = this.flows
      .stream()
      .filter(f -> this.configuration.getAuthenticationFlows().contains(f.name()))
      .filter(f -> f.grantType().equals(grantType) && f.canAuthenticate(request))
      .findFirst();

    if (!flow.isPresent()) {
      this.logAdapter
        .newWarningEntry(
          LogEvents.API_TOKEN,
          String.format(
            "No suitable flow found for grant type '%s' (enabled flows: %s)",
            grantType,
            String.join(", ", this.configuration.getAuthenticationFlows())))
        .write();

      throw new IllegalArgumentException(
        String.format("No suitable flow found for grant type '%s'", grantType)
      );
    }

    //
    // Run flow to authenticate the user or client.
    //
    try {
      var response = flow.get().authenticate(request);

      this.logAdapter
        .newInfoEntry(
          LogEvents.API_TOKEN,
          String.format("Issued value for client '%s'", response.client().clientId()))
        .write();

      return response;
    }
    catch (Exception e)
    {
      this.logAdapter
        .newErrorEntry(
          LogEvents.API_TOKEN,
          String.format("Authentication flow failed: %s", Exceptions.getFullMessage(e)))
        .write();

      throw (Exception) e.fillInStackTrace();
    }

    // TODO: Add flag to get response/errors in https://google.aip.dev/auth/4117 format
  }
}
