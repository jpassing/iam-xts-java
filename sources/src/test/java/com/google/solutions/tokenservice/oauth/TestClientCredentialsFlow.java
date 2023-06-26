package com.google.solutions.tokenservice.oauth;

import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.oauth.client.ClientPolicy;
import com.google.solutions.tokenservice.platform.LogAdapter;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.ws.rs.core.MultivaluedHashMap;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.wildfly.common.Assert.assertTrue;

public class TestClientCredentialsFlow {
  private static class Flow extends ClientCredentialsFlow
  {
    public Flow(TokenIssuer issuer) {
      super(issuer, new LogAdapter());
    }

    @Override
    public String name() {
      return "TEST";
    }

    @Override
    public String authenticationMethod() {
      return "TEST";
    }

    @Override
    protected AuthenticatedClient authenticateClient(AuthenticationRequest request) {
      return new AuthenticatedClient("client-1", Instant.now(), Map.of());
    }
  }

  private static AuthenticationRequest createRequest(String clientId)
  {
    var parameters = new MultivaluedHashMap<String, String>();
    if (clientId != null) {
      parameters.add("client_id", clientId);
    }

    return new AuthenticationRequest(
      "client_credentials",
      parameters);
  }

  // -------------------------------------------------------------------------
  // canAuthenticate.
  // -------------------------------------------------------------------------

  @Test
  public void whenClientIdMissing_thenCanAuthenticateReturnsFalse()
  {
    var flow = new Flow(
      Mockito.mock(TokenIssuer.class));

    var request = createRequest(null);
    assertFalse(flow.canAuthenticate(request));
  }

  @Test
  public void whenClientIdEmpty_thenCanAuthenticateReturnsFalse()
  {
    var flow = new Flow(
      Mockito.mock(TokenIssuer.class));

    var request = createRequest("");
    assertFalse(flow.canAuthenticate(request));
  }

  //---------------------------------------------------------------------------
  // authenticate.
  //---------------------------------------------------------------------------

  @Test
  public void whenAuthenticationFails_thenAuthenticateThrowsException() {
    var flow = new Flow(Mockito.mock(TokenIssuer.class)) {
      @Override
      protected AuthenticatedClient authenticateClient(AuthenticationRequest request) {
        throw new RuntimeException("fail");
      }
    };

    assertThrows(
      Authentication.InvalidClientException.class,
      () -> flow.authenticate(createRequest("client-1")));
  }

  @Test
  public void whenAuthenticationSucceeds_thenAuthenticateIssuesIdToken() throws Exception {
    var issuer = Mockito.mock(TokenIssuer.class);
    when(issuer.issueIdToken(any(), any()))
      .thenReturn(new IdToken("id-token", Instant.now(), Instant.now()));

    var flow = new Flow(issuer);
    var authentication = flow.authenticate(createRequest("client-1"));

    assertNotNull(authentication.client());
    assertNotNull(authentication.idToken());
    assertNull(authentication.accessToken());
  }

  @Test
  public void whenScopeProvided_thenAuthenticateIssuesStsAccessToken() {
    assertTrue(false);

  }

  @Test
  public void whenScopeAndServiceAccountProvided_thenAuthenticateIssuesServiceAccountToken() {
    assertTrue(false);

  }
}
