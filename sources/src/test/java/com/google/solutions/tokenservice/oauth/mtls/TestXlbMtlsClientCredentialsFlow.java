package com.google.solutions.tokenservice.oauth.mtls;

import com.google.solutions.tokenservice.oauth.AuthenticationRequest;
import com.google.solutions.tokenservice.oauth.IdTokenIssuer;
import com.google.solutions.tokenservice.oauth.WorkloadIdentityPool;
import com.google.solutions.tokenservice.oauth.client.ClientPolicy;
import com.google.solutions.tokenservice.oauth.mtls.XlbMtlsClientCredentialsFlow;
import com.google.solutions.tokenservice.platform.LogAdapter;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.impl.headers.HeadersMultiMap;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.core.MultivaluedHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.wildfly.common.Assert.assertTrue;

public class TestXlbMtlsClientCredentialsFlow {
  private static final XlbMtlsClientCredentialsFlow.Options OPTIONS
    = new XlbMtlsClientCredentialsFlow.Options(
      "X-ClientId",
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
  public void whenMtlsHeadersMissing_thenCanAuthenticateReturnsFalse()
  {
    var headers = new HeadersMultiMap();
    var httpRequest = Mockito.mock(HttpServerRequest.class);
    when(httpRequest.headers()).thenReturn(headers);

    var flow = new XlbMtlsClientCredentialsFlow(
      OPTIONS,
      Mockito.mock(ClientPolicy.class),
      Mockito.mock(IdTokenIssuer.class),
      Mockito.mock(WorkloadIdentityPool.class),
      httpRequest,
      new LogAdapter());

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
      Mockito.mock(ClientPolicy.class),
      Mockito.mock(IdTokenIssuer.class),
      Mockito.mock(WorkloadIdentityPool.class),
      httpRequest,
      new LogAdapter());

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
      Mockito.mock(ClientPolicy.class),
      Mockito.mock(IdTokenIssuer.class),
      Mockito.mock(WorkloadIdentityPool.class),
      httpRequest,
      new LogAdapter());

    var request = createRequest("client-1");
    assertTrue(flow.canAuthenticate(request));
  }

  // -------------------------------------------------------------------------
  // verifyRequest.
  // -------------------------------------------------------------------------

  @Test
  public void whenMtlsCertChainVerifiedHeaderIsFalse_thenVerifyClientCertificateThrowsException()
  {
    var headers = new HeadersMultiMap();
    headers.add(OPTIONS.clientCertPresentHeaderName(), "TRuE");
    headers.add(OPTIONS.clientCertChainVerifiedHeaderName(), "nottrue");

    var httpRequest = Mockito.mock(HttpServerRequest.class);
    when(httpRequest.headers()).thenReturn(headers);

    var flow = new XlbMtlsClientCredentialsFlow(
      OPTIONS,
      Mockito.mock(ClientPolicy.class),
      Mockito.mock(IdTokenIssuer.class),
      Mockito.mock(WorkloadIdentityPool.class),
      httpRequest,
      new LogAdapter());

    var request = createRequest("client-1");
    assertThrows(
      ForbiddenException.class,
      () -> flow.verifyClientCertificate(request));
  }

  @Test
  public void whenMtlsCertChainVerifiedHeaderIsTrueButClientIdMissing_thenVerifyClientCertificateThrowsException()
  {
    var headers = new HeadersMultiMap();
    headers.add(OPTIONS.clientCertPresentHeaderName(), "TRuE");
    headers.add(OPTIONS.clientCertChainVerifiedHeaderName(), "TRue");
    headers.add(OPTIONS.clientCertSpiffeIdHeaderName(), "spiffe-1");

    var httpRequest = Mockito.mock(HttpServerRequest.class);
    when(httpRequest.headers()).thenReturn(headers);

    var flow = new XlbMtlsClientCredentialsFlow(
      OPTIONS,
      Mockito.mock(ClientPolicy.class),
      Mockito.mock(IdTokenIssuer.class),
      Mockito.mock(WorkloadIdentityPool.class),
      httpRequest,
      new LogAdapter());

    var request = createRequest("client-1");
    assertThrows(
      ForbiddenException.class,
      () -> flow.verifyClientCertificate(request));
  }

  @Test
  public void whenMtlsCertChainVerifiedHeaderIsTrue_thenVerifyClientCertificateReturnsAttributes()
  {
    var headers = new HeadersMultiMap();
    headers.add(OPTIONS.clientCertPresentHeaderName(), "TRuE");
    headers.add(OPTIONS.clientCertChainVerifiedHeaderName(), "TRue");
    headers.add(OPTIONS.clientCertSpiffeIdHeaderName(), "spiffe-1");
    headers.add(OPTIONS.clientIdHeaderName(), "spiffe-1");

    var httpRequest = Mockito.mock(HttpServerRequest.class);
    when(httpRequest.headers()).thenReturn(headers);

    var flow = new XlbMtlsClientCredentialsFlow(
      OPTIONS,
      Mockito.mock(ClientPolicy.class),
      Mockito.mock(IdTokenIssuer.class),
      Mockito.mock(WorkloadIdentityPool.class),
      httpRequest,
      new LogAdapter());

    var request = createRequest("client-1");

    var attributes = flow.verifyClientCertificate(request);

    assertNotNull(attributes);
    assertEquals("spiffe-1", attributes.spiffeId());
  }
}
