package com.google.solutions.tokenservice.flows;

import com.fasterxml.jackson.annotation.JsonProperty;

public record TokenError(
  @JsonProperty("error")
  String error,

  @JsonProperty("error_description")
  String description
) {

  public static final String ACCESS_DENIED = "access_denied";
  public static final String INVALID_REQUEST = "invalid_request";
  public static final String SERVER_ERROR = "server_error";
}
