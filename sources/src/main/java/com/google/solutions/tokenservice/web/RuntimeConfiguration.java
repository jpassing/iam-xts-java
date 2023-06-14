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

import com.google.solutions.tokenservice.oauth.XlbMtlsClientCredentialsFlow;

import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class RuntimeConfiguration {
  private final Function<String, String> readSetting;

  private final StringSetting authenticationFlows = new StringSetting(
    List.of("AUTH_FLOWS"),
    XlbMtlsClientCredentialsFlow.NAME);

  //
  // Names of mTLS headers. The header names are configurable, cf.
  // https://cloud.google.com/load-balancing/docs/https/setting-up-mtls-global-ext-https#add-custom-header
  //

  public final StringSetting mtlsClientCertPresentHeader = new StringSetting(
    List.of("MTLS_HEADER_CLIENT_CERT_PRESENT"),
    "X-Client-Cert-Present");
  public final StringSetting mtlsClientCertChainVerifiedHeader = new StringSetting(
    List.of("MTLS_HEADER_CLIENT_CERT_CHAIN_VERIFIED"),
    "X-Client-Cert-Chain-Verified");
  public final StringSetting mtlsClientCertErrorHeader = new StringSetting(
    List.of("MTLS_HEADER_CLIENT_CERT_ERROR"),
    "X-Client-Cert-Error");
  public final StringSetting mtlsClientCertHashHeader = new StringSetting(
    List.of("MTLS_HEADER_CLIENT_CERT_SHA256_FINGERPRINT"),
    "X-Client-Cert-Hash");
  public final StringSetting mtlsClientCertSpiffeIdHeader = new StringSetting(
    List.of("MTLS_HEADER_CLIENT_CERT_SPIFFE_ID"),
    "X-Client-Cert-Spiffe");
  public final StringSetting mtlsClientCertUriSansHeader = new StringSetting(
    List.of("MTLS_HEADER_client_cert_uri_sans"),
    "X-Client-Cert-URI-SANs");
  public final StringSetting mtlsClientCertDnsSansHeader = new StringSetting(
    List.of("MTLS_HEADER_CLIENT_CERT_DNSNAME_SANS"),
    "X-Client-Cert-DNSName-SANs");
  public final StringSetting mtlsClientCertSerialNumberHeader = new StringSetting(
    List.of("MTLS_HEADER_CLIENT_CERT_SERIAL_NUMBER"),
    "X-Client-Cert-Serial-Number");
  public final StringSetting mtlsClientCertNotBeforeHeader = new StringSetting(
    List.of("MTLS_HEADER_CLIENT_CERT_VALID_NOT_BEFORE"),
    "X-Client-Cert-Valid-Not-Before");
  public final StringSetting mtlsClientCertNotAfterHeader = new StringSetting(
    List.of("MTLS_HEADER_CLIENT_CERT_VALID_NOT_AFTER"),
    "X-Client-Cert-Valid-Not-After");

  public RuntimeConfiguration(Map<String, String> settings) {
    this(key -> settings.get(key));
  }

  public RuntimeConfiguration(Function<String, String> readSetting) {
    this.readSetting = readSetting;
  }

  // -------------------------------------------------------------------------
  // Settings.
  // -------------------------------------------------------------------------

  /**
   * List of enabled authentication flows.
   */
  public Set<String> getAuthenticationFlows()
  {
    return Arrays.stream(this.authenticationFlows.getValue()
      .split(","))
      .filter(s -> !s.isEmpty())
      .map(s -> s.trim())
      .collect(Collectors.toSet());
  }

  // -------------------------------------------------------------------------
  // Inner classes.
  // -------------------------------------------------------------------------

  public abstract class Setting<T> {
    private final Collection<String> keys;
    private final T defaultValue;

    protected abstract T parse(String value);

    protected Setting(Collection<String> keys, T defaultValue) {
      this.keys = keys;
      this.defaultValue = defaultValue;
    }

    public T getValue() {
      for (var key : this.keys) {
        var value = readSetting.apply(key);
        if (value != null) {
          value = value.trim();
          if (!value.isEmpty()) {
            return parse(value);
          }
        }
      }

      if (this.defaultValue != null) {
        return this.defaultValue;
      }
      else {
        throw new IllegalStateException("No value provided for " + this.keys);
      }
    }

    public boolean isValid() {
      try {
        getValue();
        return true;
      }
      catch (Exception ignored) {
        return false;
      }
    }
  }

  public class StringSetting extends Setting<String> {
    public StringSetting(Collection<String> keys, String defaultValue) {
      super(keys, defaultValue);
    }

    @Override
    protected String parse(String value) {
      return value;
    }
  }

  public class IntSetting extends Setting<Integer> {
    public IntSetting(Collection<String> keys, Integer defaultValue) {
      super(keys, defaultValue);
    }

    @Override
    protected Integer parse(String value) {
      return Integer.parseInt(value);
    }
  }

  public class BooleanSetting extends Setting<Boolean> {
    public BooleanSetting(Collection<String> keys, Boolean defaultValue) {
      super(keys, defaultValue);
    }

    @Override
    protected Boolean parse(String value) {
      return Boolean.parseBoolean(value);
    }
  }

  public class DurationSetting extends Setting<Duration> {
    public DurationSetting(Collection<String> keys, Duration defaultValue) {
      super(keys, defaultValue);
    }

    @Override
    protected Duration parse(String value) {
      return Duration.ofMinutes(Integer.parseInt(value));
    }
  }
}
