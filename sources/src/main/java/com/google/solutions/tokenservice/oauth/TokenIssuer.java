package com.google.solutions.tokenservice.oauth;

import com.google.common.base.Preconditions;
import com.google.solutions.tokenservice.platform.ServiceAccount;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class TokenIssuer {
  private final ServiceAccount serviceAccount;

  public TokenIssuer(ServiceAccount serviceAccount) {
    Preconditions.checkNotNull(serviceAccount, "serviceAccount");

    this.serviceAccount = serviceAccount;
  }

  public ServiceAccount getServiceAccount() {
    return serviceAccount;
  }
}
