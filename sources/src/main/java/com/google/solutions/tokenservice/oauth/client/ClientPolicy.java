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
 * Policy for authenticating clients.
 *
 * This class contains an example implementation. A real implementation
 * might use an inventory database or configuration file to authenticate
 * clients.
 */
@ApplicationScoped
public class ClientPolicy {
  public ClientPolicy() {
  }

  /**
   * Authorize a client that has previously authenticated using mTLS.
   *
   * @param clientId clientId conveyed in request.
   * @param attributes attributes conveyed in client certificate.
   * @return Client if successful.
   * @throws if the client is unknown of the attributes are invalid.
   */
  public AuthorizedClient authorizeClient(
    String clientId,
    MtlsClientCertificate attributes
  )
  {
    //
    // The client has successfully authenticated by presenting a trusted
    // mTLS client certificate. In this example implementation, we consider
    // that sufficient, and simply use the certificate attributes as
    // client claims.
    //
    // In a real-world scenario, we could perform additional checks here,
    // such as:
    //
    // - check the certificate hash against an allow-list of device registry
    // - require specific attributes (such as Spiffe ID) to be provided
    //
    // Also, we could transform or enrich the set of claims, for example by
    // looking up additional client/device information in a database.
    //

    var claims = new HashMap<String, String>();
    claims.put("x5_spiffe", attributes.spiffeId());
    claims.put("x5_dnssan", attributes.sanDns());
    claims.put("x5_urisan", attributes.sanUri());
    claims.put("x5_sha256", attributes.sha256fingerprint());
    claims.put("x5_serial", attributes.serialNumber());

    return new AuthorizedClient(
      clientId,
      Instant.now(),
      claims);
  }
}
