package com.google.solutions.tokenservice.oauth;

import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.oauth.client.ClientPolicy;
import com.google.solutions.tokenservice.platform.LogAdapter;
import com.google.solutions.tokenservice.platform.WorkloadIdentityPool;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import javax.ws.rs.core.MultivaluedHashMap;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.wildfly.common.Assert.assertTrue;

public class TestClientCredentialsFlow {
  private static class Flow extends ClientCredentialsFlow
  {
    public Flow(TokenIssuer issuer, WorkloadIdentityPool pool) {
      super(
        issuer,
        pool,
        new LogAdapter());
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
      Mockito.mock(TokenIssuer.class),
      Mockito.mock(WorkloadIdentityPool.class));

    var request = createRequest(null);
    assertFalse(flow.canAuthenticate(request));
  }

  @Test
  public void whenClientIdEmpty_thenCanAuthenticateReturnsFalse()
  {
    var flow = new Flow(
      Mockito.mock(TokenIssuer.class),
      Mockito.mock(WorkloadIdentityPool.class));

    var request = createRequest("");
    assertFalse(flow.canAuthenticate(request));
  }

  //---------------------------------------------------------------------------
  // authenticate.
  //---------------------------------------------------------------------------

  @Test
  public void whenAuthenticationFails_thenAuthenticateThrowsException() {
    var flow = new Flow(
      Mockito.mock(TokenIssuer.class),
      Mockito.mock(WorkloadIdentityPool.class)
    ) {
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
    var idToken = new IdToken("id-token", Instant.now(), Instant.MAX);

    var issuer = Mockito.mock(TokenIssuer.class);
    when(issuer.issueIdToken(any(), any())).thenReturn(idToken);

    var flow = new Flow(
      issuer,
      Mockito.mock(WorkloadIdentityPool.class));
    var authentication = flow.authenticate(createRequest("client-1"));

    assertNotNull(authentication.client());
    assertNotNull(authentication.idToken());
    assertSame(idToken, authentication.idToken());
    assertNull(authentication.accessToken());
  }

  @Test
  public void whenScopeProvided_thenAuthenticateIssuesStsAccessToken() throws Exception {
    var idToken = new IdToken("id-token", Instant.now(), Instant.MAX);
    var accessToken = new AccessToken("access-token", "scope-1", Instant.now(), Instant.MAX);

    var issuer = Mockito.mock(TokenIssuer.class);
    when(issuer.issueIdToken(any(), any())).thenReturn(idToken);

    var pool = Mockito.mock(WorkloadIdentityPool.class);
    when(pool.issueAccessToken(same(idToken), eq("scope-1"))).thenReturn(accessToken);

    var flow = new Flow(issuer, pool);

    var parameters = new MultivaluedHashMap<String, String>();
    parameters.add("client_id", "client-1");
    parameters.add("scope", "scope-1");

    var authentication = flow.authenticate(
      new AuthenticationRequest("client_credentials", parameters));

    assertNotNull(authentication.client());
    assertNotNull(authentication.idToken());
    assertNotNull(authentication.accessToken());
    assertSame(accessToken, authentication.accessToken());
  }

  @Test
  public void whenScopeAndServiceAccountProvided_thenAuthenticateIssuesServiceAccountToken() {
    assertTrue(false);

  }
}
