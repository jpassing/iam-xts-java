package com.google.solutions.tokenservice.oauth;

import com.google.auth.oauth2.TokenVerifier;
import com.google.solutions.tokenservice.URLHelper;
import com.google.solutions.tokenservice.oauth.client.AuthorizedClient;
import com.google.solutions.tokenservice.oauth.client.ClientPolicy;
import com.google.solutions.tokenservice.platform.IntegrationTestEnvironment;
import com.google.solutions.tokenservice.platform.LogAdapter;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.core.MultivaluedHashMap;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class TestMtlsClientCredentialsFlow {
  private static final URL ISSUER_ID = URLHelper.fromString("http://example.com/");

  private class Flow extends  MtlsClientCredentialsFlow
  {
    public Flow(ClientPolicy clientRepository, TokenIssuer issuer) {
      super(clientRepository, issuer, new LogAdapter());
    }

    @Override
    public String name() {
      return "TEST";
    }

    @Override
    protected MtlsClientCertificate verifyClientCertificate(TokenRequest request) {
      return new MtlsClientCertificate(null, null, null, null, null, null, null);
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
      Mockito.mock(ClientPolicy.class),
      Mockito.mock(TokenIssuer.class));

    var request = createRequest(null);
    assertFalse(flow.canAuthenticate(request));
  }

  @Test
  public void whenClientIdEmpty_thenCanAuthenticateReturnsFalse()
  {
    var flow = new Flow(
      Mockito.mock(ClientPolicy.class),
      Mockito.mock(TokenIssuer.class));

    var request = createRequest("");
    assertFalse(flow.canAuthenticate(request));
  }

  // -------------------------------------------------------------------------
  // authenticate.
  // -------------------------------------------------------------------------

  @Test
  public void whenClientRepositoryFailsToAuthenticate_thenAuthenticateThrowsException() {
    var clientRepository = Mockito.mock(ClientPolicy.class);
    when(clientRepository.authorizeClient(eq("client-1"), any()))
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
    var client = new AuthorizedClient(
      "client-1",
      Instant.ofEpochSecond(1000),
      new HashMap<>());

    var clientRepository = Mockito.mock(ClientPolicy.class);
    when(clientRepository.authorizeClient(eq("client-1"), any()))
      .thenReturn(client);

    var issuer = new TokenIssuer(
      new TokenIssuer.Options(ISSUER_ID, Duration.ofMinutes(1)),
      IntegrationTestEnvironment.SERVICE_ACCOUNT);

    var flow = new Flow(
      clientRepository,
      issuer);

    var response = flow.authenticate(createRequest("client-1"));
    assertSame(client, response.client());
    assertEquals("Bearer", response.accessTokenType());
    assertNotNull(response.idToken());

    var verifiedPayload = TokenVerifier
      .newBuilder()
      .setCertificatesLocation(issuer.jwksUrl().toString())
      .setIssuer(issuer.id().toString())
      .setAudience("client-1")
      .build()
      .verify(response.idToken().value())
      .getPayload();
    assertEquals(flow.name().toLowerCase(), verifiedPayload.get("amr"));
  }
}
