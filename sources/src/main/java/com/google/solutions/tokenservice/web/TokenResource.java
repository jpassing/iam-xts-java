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

import com.google.common.base.Strings;
import com.google.solutions.tokenservice.Exceptions;
import com.google.solutions.tokenservice.adapters.LogAdapter;
import com.google.solutions.tokenservice.oauth.AuthenticationFlow;
import com.google.solutions.tokenservice.oauth.TokenRequest;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;

/**
 * REST API controller.
 */
@Dependent
@Path("/token")
public class TokenResource {
  @Inject
  RuntimeEnvironment runtimeEnvironment;

  @Inject
  LogAdapter logAdapter;

  @Inject
  Instance<AuthenticationFlow> flows;

  // -------------------------------------------------------------------------
  // REST resources.
  // -------------------------------------------------------------------------

  /**
   */
//  @GET
//  @Produces(MediaType.APPLICATION_JSON)
//  @Path("test")
//  public TestResponse getPolicy(
//    @Context SecurityContext securityContext
//  ) {
//    return new TestResponse("Test");
//  }

  @POST
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  public Response post(
    @Context HttpHeaders headers,
    @FormParam("grant_type") String grantType,
    MultivaluedMap<String, String> parameters
  ) throws Exception {
    if (Strings.isNullOrEmpty(grantType))
    {
      throw new IllegalArgumentException("A grant type is required");
    }

    //
    // Find a suitable flow for this set of parameters.
    //
    var request = new TokenRequest(grantType, parameters);
    var flow = this.flows
      .stream()
      .filter(f -> f.isAvailable(request))
      .findFirst();

    if (!flow.isPresent()) {
      throw new IllegalArgumentException("The parameters are incomplete for this grant type");
    }

    //
    // Authenticate.
    //
    try {
      return Response
        .ok(flow.get().authenticate(request))
        .build();
    }
    catch (Exception e)
    {
      this.logAdapter
        .newErrorEntry(
          LogEvents.API_TOKEN,
          String.format("Authentication failed: %s", Exceptions.getFullMessage(e)))
        .write();

      throw (Exception) e.fillInStackTrace();
    }
  }
}
