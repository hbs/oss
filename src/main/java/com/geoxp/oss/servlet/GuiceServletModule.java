package com.geoxp.oss.servlet;

import com.google.inject.servlet.ServletModule;

public class GuiceServletModule extends ServletModule {
  @Override
  protected void configureServlets() {
    serve("/GenMasterSecret").with(GenMasterSecretServlet.class);
    serve("/Init").with(InitServlet.class);
    serve("/GetSecret").with(GetSecretServlet.class);
    serve("/GenSecret").with(GenSecretServlet.class);
    serve("/GetOSSRSA").with(GetOSSRSAServlet.class);
  }
}
