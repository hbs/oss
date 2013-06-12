package com.geoxp.oss.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.CryptoHelper.SSHAgentClient;
import com.geoxp.oss.CryptoHelper.SSHAgentClient.SSHKey;
import com.geoxp.oss.client.OSSClient;

public class OSSSshAgentAddIdentity {
  private static class DefaultPasswordFinder implements PasswordFinder {

    private final char[] password;

    private DefaultPasswordFinder(char [] password) {
      this.password = password;
    }

    @Override
    public char[] getPassword() {
      return Arrays.copyOf(password, password.length);
    }
  } 
  
  final static String[] SSH_DEFAULT_KEY_FILENAMES = {"id_dsa", "id_rsa" };

  private static List<File> getDefaultsKeyFiles() {
    String sshDir = System.getProperty("user.home") + File.separator + ".ssh";
    ArrayList<File> result = new ArrayList<File>();

    for (String sshKeyFilename : SSH_DEFAULT_KEY_FILENAMES) {
      File file = new File(sshDir, sshKeyFilename);
      if (file.canRead()) {
        result.add(file);
      }
    }

    return result;		
  }

  /**
   * @param args
   */
  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      System.err.println("Usage: OSSLoadAgent OSS_URL SECRET_NAME WRAPPED_PASSPHRASE AGENT_AUTH_SOCK [KEY_FILE]");
      System.exit(1);
    }

    SSHAgentClient sshAgent = new SSHAgentClient(args[2]);

    /* Get the secret from OSS */
    /* FIXME ? Provide a way to specify the ssh signing key fingerprint */
    byte[] secret = OSSClient.getSecret(args[0], args[1], null);
    // Use the secret to unwrap the passphrase
    byte[] unwrap = CryptoHelper.unwrapAES(secret, Hex.decode(args[3]), true);
    String password = new String(unwrap, "UTF-8");

    /* Read private keys */
    /* openssh store it in PEM format */		
    List<File> sshKeyFiles;
    if (args.length > 4) {
      sshKeyFiles = new ArrayList<File>(1);
      sshKeyFiles.add(new File(args[4]));
    } else {
      sshKeyFiles = getDefaultsKeyFiles();
    }

    for (File sshKeyFile : sshKeyFiles) {
      Reader fRd = new BufferedReader(new FileReader(sshKeyFile));
      PEMReader pem = new PEMReader(fRd, new DefaultPasswordFinder(password.toCharArray()), "BC");

      Object o;
      try {
        while ((o = pem.readObject()) != null) {
          if (o instanceof KeyPair) {
            KeyPair kp = (KeyPair) o;
            /* Add the identity in the ssh-agent */
            byte[] keyblob = CryptoHelper.sshKeyBlobFromKeyPair(kp);
            System.out.println("Loading " + sshKeyFile.getPath());
            sshAgent.addIdentity(keyblob, sshKeyFile.getPath());
          }
        }
      } catch (EncryptionException ee) {
        System.err.println("Can't read private key in " + sshKeyFile.getAbsolutePath());
      }

      pem.close();
    }

    System.out.println("Keys in agent :");
    List<SSHKey> identities = sshAgent.requestIdentities();
    for (SSHKey identity : identities) {
      System.out.println(identity);
    }

  }

}
