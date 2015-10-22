import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
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
    public void encrypt_decrypt_jce() throws Exception {
        String plain = "This is very private.";
        System.out.println("plain: " + plain);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(KEY_SIZE_IN_BITS);
        KeyPair keyPair = generator.generateKeyPair();

        RSAEngine rsa = new RSAEngine();

        rsa.init(true, PublicKeyFactory.createKey(keyPair.getPublic().getEncoded()));

        byte[] cipher = rsa.processBlock(plain.getBytes(), 0, plain.getBytes().length);
        System.out.println("cipher: " + Hex.toHexString(cipher));

        rsa.init(false, PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded()));

        byte[] decrypted = rsa.processBlock(cipher, 0, cipher.length);
        String encryptionString = new String(decrypted);
        System.out.println("encryption: " + encryptionString);

        assertThat(encryptionString).isEqualTo(plain);
    }

    @Test
    public void encrypt_decrypt_bcintern() throws Exception {
        String plain = "This is really private using plain bc.";
        System.out.println("plain: " + plain);

        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        BigInteger publicExponent = BigInteger.valueOf(3);
				SecureRandom prng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        RSAKeyGenerationParameters parameters = new RSAKeyGenerationParameters(publicExponent, prng, KEY_SIZE_IN_BITS, 80);
        generator.init(parameters);

        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        RSAEngine rsa = new RSAEngine();

        rsa.init(true, keyPair.getPublic());
        byte[] cipher = rsa.processBlock(plain.getBytes(), 0, plain.getBytes().length);
        System.out.println("cipher: " + Hex.toHexString(cipher));

        rsa.init(false, keyPair.getPrivate());
        byte[] decrypted = rsa.processBlock(cipher, 0, cipher.length);

        String decriptionString = new String(decrypted);
        System.out.println("encryption: " + decriptionString);

        assertThat(decriptionString).isEqualTo(plain);
    }
}
