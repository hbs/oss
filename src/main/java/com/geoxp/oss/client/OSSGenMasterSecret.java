package com.geoxp.oss.client;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class OSSGenMasterSecret {
  public static void main(String[] args) throws Exception {
    if (4 != args.length) {
      System.err.println("Usage: OSSGenMasterSecret OSS_GEN_MASTER_SECRET_URL PATH_TO_PUBRINGS PGP_KEY_IDS K");
      System.exit(1);
    }
    
    String[] keyids = args[2].split(",");
    
    List<String> pgpkeyids = new ArrayList<String>();
    
    for (String keyid: keyids) {
      pgpkeyids.add(keyid);
    }
    
    String[] pubrings = args[1].split(",");

    List<String> pgppubrings = new ArrayList<String>();
    
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    byte[] buf = new byte[1024];
    
    for (String pubring: pubrings) {
      InputStream is = new FileInputStream(pubring);
      baos.reset();
      
      do {
        int len = is.read(buf);
        
        if (len < 0) {
          break;
        }
        
        baos.write(buf, 0, len);
      } while (true);
      
      is.close();
      baos.close();
    
      pgppubrings.add(new String(baos.toByteArray(), "UTF-8"));
    }

    Map<String,String> shares = OSSClient.genMasterSecret(args[0], pgppubrings, pgpkeyids, Integer.valueOf(args[3]));
    
    for (Entry<String,String> entry: shares.entrySet()) {
      System.out.println();
      System.out.println("[" + entry.getKey() + "]");
      System.out.println();
      System.out.println(entry.getValue());
    }
  }
}
