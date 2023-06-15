package com.google.solutions.tokenservice.oauth;

import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.oauth.client.ClientRepository;
import com.google.solutions.tokenservice.platform.IntegrationTestEnvironment;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.impl.headers.HeadersMultiMap;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.core.MultivaluedHashMap;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class TestMtlsClientCredentialsFlow {
  private class Flow extends  MtlsClientCredentialsFlow
  {
    public Flow(ClientRepository clientRepository, TokenIssuer issuer) {
      super(clientRepository, issuer);
    }

    @Override
    public String name() {
      return "TEST";
    }

    @Override
    protected MtlsClientAttributes verifyRequest(TokenRequest request) {
      return new MtlsClientAttributes(null, null, null, null, null, null, null);
    }
  }

  private static TokenRequest createRequest(String clientId)
  {
    var parameters = new MultivaluedHashMap<String, String>();
    if (clientId != null) {
      parameters.add("client_id", clientId);
    }

    return new TokenRequest(
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
      Mockito.mock(ClientRepository.class),
      Mockito.mock(TokenIssuer.class));

    var request = createRequest(null);
    assertFalse(flow.canAuthenticate(request));
  }

  @Test
  public void whenClientIdEmpty_thenCanAuthenticateReturnsFalse()
  {
    var flow = new Flow(
      Mockito.mock(ClientRepository.class),
      Mockito.mock(TokenIssuer.class));

    var request = createRequest("");
    assertFalse(flow.canAuthenticate(request));
  }

  // -------------------------------------------------------------------------
  // authenticate.
  // -------------------------------------------------------------------------

  @Test
  public void whenClientRepositoryFailsToAuthenticate_thenAuthenticateThrowsException() {
    var clientRepository = Mockito.mock(ClientRepository.class);
    when(clientRepository.authenticateClient(eq("client-1"), any()))
      .thenThrow(new RuntimeException("mock"));

    var flow = new Flow(
      clientRepository,
      Mockito.mock(TokenIssuer.class));

    assertThrows(
      ForbiddenException.class,
      () -> flow.authenticate(createRequest("client-1")));
  }

  @Test
  public void whenClientRepositoryAuthenticatesClient_thenAuthenticateReturnsToken() throws Exception {
    var client = new AuthenticatedClient(
      "client-1",
      Instant.ofEpochSecond(1000),
      new HashMap<>());

    var clientRepository = Mockito.mock(ClientRepository.class);
    when(clientRepository.authenticateClient(eq("client-1"), any()))
      .thenReturn(client);

    var flow = new Flow(
      clientRepository,
      new TokenIssuer(
        new TokenIssuer.Options(Duration.ofMinutes(1)),
        IntegrationTestEnvironment.SERVICE_ACCOUNT));

    var response = flow.authenticate(createRequest("client-1"));
    assertSame(client, response.client());
    assertEquals("Bearer", response.tokenType());
    assertNotNull(response.accessToken());
  }
}
