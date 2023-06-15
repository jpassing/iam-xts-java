package com.google.solutions.tokenservice.oauth;

import javax.ws.rs.core.MultivaluedMap;

public record TokenRequest(
  String grantType,
  MultivaluedMap<String, String> parameters) {

}
