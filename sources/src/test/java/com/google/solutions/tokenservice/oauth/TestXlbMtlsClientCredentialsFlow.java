package com.google.solutions.tokenservice.oauth;

import com.google.solutions.tokenservice.oauth.client.ClientRepository;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.impl.headers.HeadersMultiMap;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.core.MultivaluedHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.wildfly.common.Assert.assertTrue;

public class TestXlbMtlsClientCredentialsFlow {
  private static final XlbMtlsClientCredentialsFlow.Options OPTIONS 
    = new XlbMtlsClientCredentialsFlow.Options(
      "X-CertPresent",
      "X-CertChainVerified",
      "X-CertError",
      "X-CertSpiffeId",
      "X-CertDnsSans",
      "X-CertUriSans",
      "X-CertHash",
      "X-CertSerialNumber",
      "X-CertNotBefore",
      "X-CertNotAfter"
    );

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
  public void whenMtlsHeadersMissing_thenCanAuthenticateReturnsFalse()
  {
    var headers = new HeadersMultiMap();
    var httpRequest = Mockito.mock(HttpServerRequest.class);
    when(httpRequest.headers()).thenReturn(headers);

    var flow = new XlbMtlsClientCredentialsFlow(
      OPTIONS,
      Mockito.mock(ClientRepository.class),
      Mockito.mock(TokenIssuer.class),
      httpRequest);

    var request = createRequest("client-1");
    assertFalse(flow.canAuthenticate(request));
  }

  @Test
  public void whenMtlsCertPresentHeaderIsFalse_thenCanAuthenticateReturnsFalse()
  {
    var headers = new HeadersMultiMap();
    headers.add(OPTIONS.clientCertPresentHeaderName(), "false");

    var httpRequest = Mockito.mock(HttpServerRequest.class);
    when(httpRequest.headers()).thenReturn(headers);

    var flow = new XlbMtlsClientCredentialsFlow(
      OPTIONS,
      Mockito.mock(ClientRepository.class),
      Mockito.mock(TokenIssuer.class),
      httpRequest);

    var request = createRequest("client-1");
    assertFalse(flow.canAuthenticate(request));
  }

  @Test
  public void whenMtlsCertPresentHeaderIsTrue_thenCanAuthenticateReturnsTrue()
  {
    var headers = new HeadersMultiMap();
    headers.add(OPTIONS.clientCertPresentHeaderName(), "TRuE");

    var httpRequest = Mockito.mock(HttpServerRequest.class);
    when(httpRequest.headers()).thenReturn(headers);

    var flow = new XlbMtlsClientCredentialsFlow(
      OPTIONS,
      Mockito.mock(ClientRepository.class),
      Mockito.mock(TokenIssuer.class),
      httpRequest);

    var request = createRequest("client-1");
    assertTrue(flow.canAuthenticate(request));
  }

  @Test
  public void whenClientIdMissing_thenCanAuthenticateReturnsFalse()
  {
    var headers = new HeadersMultiMap();
    headers.add(OPTIONS.clientCertPresentHeaderName(), "TRuE");

    var httpRequest = Mockito.mock(HttpServerRequest.class);
    when(httpRequest.headers()).thenReturn(headers);

    var flow = new XlbMtlsClientCredentialsFlow(
      OPTIONS,
      Mockito.mock(ClientRepository.class),
      Mockito.mock(TokenIssuer.class),
      httpRequest);

    var request = createRequest("");
    assertFalse(flow.canAuthenticate(request));
  }

  // -------------------------------------------------------------------------
  // verifyRequest.
  // -------------------------------------------------------------------------

  @Test
  public void whenMtlsCertChainVerifiedHeaderIsFalse_thenVerifyRequestThrowsException()
  {
    var headers = new HeadersMultiMap();
    headers.add(OPTIONS.clientCertPresentHeaderName(), "TRuE");
    headers.add(OPTIONS.clientCertChainVerifiedHeaderName(), "nottrue");

    var httpRequest = Mockito.mock(HttpServerRequest.class);
    when(httpRequest.headers()).thenReturn(headers);


    var flow = new XlbMtlsClientCredentialsFlow(
      OPTIONS,
      Mockito.mock(ClientRepository.class),
      Mockito.mock(TokenIssuer.class),
      httpRequest);

    var request = createRequest("client-1");

    assertThrows(
      ForbiddenException.class,
      () -> flow.verifyRequest(request));
  }

  @Test
  public void whenMtlsCertChainVerifiedHeaderIsTrue_thenVerifyRequestReturnsAttributes()
  {
    var headers = new HeadersMultiMap();
    headers.add(OPTIONS.clientCertPresentHeaderName(), "TRuE");
    headers.add(OPTIONS.clientCertChainVerifiedHeaderName(), "TRue");
    headers.add(OPTIONS.clientCertSpiffeIdHeaderName(), "spiffe-1");

    var httpRequest = Mockito.mock(HttpServerRequest.class);
    when(httpRequest.headers()).thenReturn(headers);


    var flow = new XlbMtlsClientCredentialsFlow(
      OPTIONS,
      Mockito.mock(ClientRepository.class),
      Mockito.mock(TokenIssuer.class),
      httpRequest);

    var request = createRequest("client-1");

    var attributes = flow.verifyRequest(request);

    assertNotNull(attributes);
    assertEquals("spiffe-1", attributes.spiffeId());
  }
}
