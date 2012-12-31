package com.geoxp.oss.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.geoxp.oss.OSS;
import com.google.gson.JsonObject;
import com.google.inject.Singleton;

@Singleton
public class GetOSSRSAServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {    
    JsonObject json = new JsonObject();
    
    json.addProperty("exponent", OSS.getSessionRSAPublicKey().getPublicExponent().toString(10));
    json.addProperty("modulus", OSS.getSessionRSAPublicKey().getModulus().toString(10));
    
    response.setContentType("application/json");
    response.getWriter().print(json.toString());
  }
}
