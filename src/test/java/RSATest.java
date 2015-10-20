import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;

public class RSATest {
    private static final int KEY_SIZE_IN_BITS = 1024;

    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @After
    public void tearDown() throws Exception {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    @Test
    public void encrypt_decrypt() throws Exception {
        String message = "This is very private.";
        System.out.println("plain: " + message);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(KEY_SIZE_IN_BITS);
        KeyPair keyPair = generator.generateKeyPair();

        RSAEngine rsa = new RSAEngine();

        rsa.init(true, PublicKeyFactory.createKey(keyPair.getPublic().getEncoded()));

        byte[] cipher = rsa.processBlock(message.getBytes(), 0, message.getBytes().length);
        System.out.println("cipher: " + getHexString(cipher));

        rsa.init(false, PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded()));

        byte[] decrypted = rsa.processBlock(cipher, 0, cipher.length);
        System.out.println("encryption: " + new String(decrypted));

        assertThat(new String(decrypted)).isEqualTo(message);
    }


    private static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (byte aB : b) {
            result += Integer.toString((aB & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }
}
