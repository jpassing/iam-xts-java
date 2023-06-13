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

import com.google.solutions.tokenservice.core.adapters.LogAdapter;
import com.google.solutions.tokenservice.flows.TokenRequest;

import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;

/**
 * REST API controller.
 */
@Dependent
@Path("/token")
public class ApiResource {
  @Inject
  RuntimeEnvironment runtimeEnvironment;

  @Inject
  LogAdapter logAdapter;

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
  public void post(
    @Context HttpHeaders headers,
    MultivaluedMap<String, String> formParams
  ) {
    var grantType = formParams.getFirst("grant_type");

    var request = new TokenRequest(headers, formParams);

  }
}
