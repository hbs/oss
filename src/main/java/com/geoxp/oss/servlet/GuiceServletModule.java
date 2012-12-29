package com.geoxp.oss.servlet;

import com.google.inject.servlet.ServletModule;

public class GuiceServletModule extends ServletModule {
  @Override
  protected void configureServlets() {
    //serve("").with(.class);
  }
}
