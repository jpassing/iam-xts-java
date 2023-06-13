package com.google.solutions.tokenservice.oauth;

import javax.ws.rs.core.MultivaluedMap;

public record TokenRequest(
  String grantTypes,
  MultivaluedMap<String, String> parameters) {

}
