package com.geoxp.oss;

public class OSSException extends Exception {
  public OSSException(String message) {
    super(message);
  }
  
  public OSSException(Throwable cause) {
    super(cause);
  }
}
