package com.google.solutions.tokenservice.oauth;

import com.google.auth.oauth2.TokenVerifier;
import com.google.solutions.tokenservice.URLHelper;
import com.google.solutions.tokenservice.oauth.client.AuthenticatedClient;
import com.google.solutions.tokenservice.oauth.client.ClientPolicy;
import com.google.solutions.tokenservice.platform.IntegrationTestEnvironment;
import com.google.solutions.tokenservice.platform.LogAdapter;
import com.google.solutions.tokenservice.platform.WorkloadIdentityPool;
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

  private static class Flow extends  MtlsClientCredentialsFlow
  {
    public Flow(ClientPolicy clientPolicy, TokenIssuer issuer) {
      super(
        clientPolicy,
        issuer,
        Mockito.mock(WorkloadIdentityPool.class),
        new LogAdapter());
    }

    @Override
    public String name() {
      return "TEST";
    }

    @Override
    protected MtlsClientCertificate verifyClientCertificate(AuthenticationRequest request) {
      return new MtlsClientCertificate(null, null, null, null, null, null, null);
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
  // authenticate.
  // -------------------------------------------------------------------------

  @Test
  public void whenClientRepositoryFailsToAuthenticate_thenAuthenticateThrowsException() {
    var clientRepository = Mockito.mock(ClientPolicy.class);
    when(clientRepository.authenticateClient(eq("client-1"), any()))
      .thenThrow(new RuntimeException("mock"));

    var flow = new Flow(
      clientRepository,
      Mockito.mock(TokenIssuer.class));

    assertThrows(
      Authentication.InvalidClientException.class,
      () -> flow.authenticate(createRequest("client-1")));
  }

  @Test
  public void whenClientRepositoryAuthenticatesClient_thenAuthenticateReturnsToken() throws Exception {
    var client = new AuthenticatedClient(
      "client-1",
      Instant.ofEpochSecond(1000),
      new HashMap<>());

    var clientRepository = Mockito.mock(ClientPolicy.class);
    when(clientRepository.authenticateClient(eq("client-1"), any()))
      .thenReturn(client);

    var issuer = new TokenIssuer(
      new TokenIssuer.Options(ISSUER_ID, null, Duration.ofMinutes(1)),
      IntegrationTestEnvironment.SERVICE_ACCOUNT);

    var flow = new Flow(
      clientRepository,
      issuer);

    var response = flow.authenticate(createRequest("client-1"));
    assertSame(client, response.client());
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
