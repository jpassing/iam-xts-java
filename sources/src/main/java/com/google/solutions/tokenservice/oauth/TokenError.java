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
