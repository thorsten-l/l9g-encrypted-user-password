package l9g.keycloak.keygen;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
public class App
{
  private final static String PRIVATE_KEY_FILENAME = "l9g-encrypted-user-password-client.pirvatekey";

  private final static String PUBLIC_KEY_FILENAME = "l9g-encrypted-user-password-server.publickey";

  public static void main(String[] args) throws Throwable
  {
    Security.addProvider(new BouncyCastleProvider());

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
    keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"),
      new SecureRandom());

    System.out.println("Generating key pair (" + keyPairGenerator.getAlgorithm()+")");
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    PublicKey publicKey = keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();

    FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_FILENAME);
    System.out.println("Writing " + PUBLIC_KEY_FILENAME);
    fos.write(publicKey.getEncoded());
    fos = new FileOutputStream(PRIVATE_KEY_FILENAME);
    System.out.println("Writing " + PRIVATE_KEY_FILENAME);
    fos.write(privateKey.getEncoded());
    System.out.println("done.");
  }
}
