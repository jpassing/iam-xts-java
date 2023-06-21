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

package com.google.solutions.tokenservice.oauth.client;

import com.google.solutions.tokenservice.oauth.MtlsClientCertificate;

import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.ForbiddenException;
import java.time.Instant;
import java.util.HashMap;

/**
 * Policy that defines which clients are allowed to authenticate.
 *
 * This is an example implementation. A real implementation might use
 * an inventory database or configuration file to authenticate clients.
 *
 */
@ApplicationScoped
public class ClientPolicy {
  public ClientPolicy() {
  }

  /**
   * Authenticate a client.
   *
   * @param clientId clientId conveyed in request.
   * @param attributes attributes conveyed in client certificate, verified
   * @return Client if successful
   * @throws if the client is unknown of the attributes are invalid
   */
  public AuthenticatedClient authenticateClient(
    String clientId,
    MtlsClientCertificate attributes
  )
  {
    //
    // In a real-world scenario, we'd use an inventory database to check
    // if the client ID exists and whether the presented attributes match
    // what we're expecting.
    //
    // Optionally, we could look up additional client metadata in the inventory
    // and return it as additional claims.
    //
    // In this sample implementation, we consider any client valid and simply
    // echo the input claims.
    //

    if (!clientId.equals(attributes.spiffeId()) &&
        !clientId.equals(attributes.sanDns()) &&
        !clientId.equals(attributes.sanUri())) {
      //
      // The client ID must match one of these attributes.
      //
      throw new ForbiddenException("The client ID is unknown");
    }

    var claims = new HashMap<String, String>();
    claims.put("x5_spiffe", attributes.spiffeId());
    claims.put("x5_dnssan", attributes.sanDns());
    claims.put("x5_urisan", attributes.sanUri());
    claims.put("x5_sha256", attributes.sha256fingerprint());
    claims.put("x5_serial", attributes.serialNumber());

    return new AuthenticatedClient(
      clientId,
      Instant.now(),
      claims);
  }
}
