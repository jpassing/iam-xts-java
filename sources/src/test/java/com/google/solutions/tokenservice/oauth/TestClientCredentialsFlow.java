package com.google.solutions.tokenservice.oauth;

import org.junit.jupiter.api.Test;

import static org.wildfly.common.Assert.assertTrue;

public class TestClientCredentialsFlow {

  //---------------------------------------------------------------------------
  // authenticate.
  //---------------------------------------------------------------------------

  @Test
  public void whenAuthenticationFails_thenAuthenticateThrowsException() {
    assertTrue(false);

  }

  @Test
  public void whenAuthenticationSucceeds_thenAuthenticateIssuesIdToken() {
    assertTrue(false);

  }

  @Test
  public void whenProviderSet_thenAuthenticateIssuesStsTokenWithDefaultScope() {
    assertTrue(false);

  }

  @Test
  public void whenProviderAndSSet_thenAuthenticateIssuesStsTokenWithScope() {
    assertTrue(false);

  }

  @Test
  public void whenProviderAndServiceAccountSet_thenAuthenticateIssuesServiceAccountToken() {
    assertTrue(false);

  }
}
