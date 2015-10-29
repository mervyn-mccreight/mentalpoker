import client.coinflip.CoinFlipClient;
import com.google.common.collect.Lists;
import generator.RandomStringGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class CoinFlipTest {

    private SecureRandom random;
    private static BigInteger p = new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16);
    private static BigInteger q = new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16);

    @Before
    public void setUp() throws Exception {
        random = SecureRandom.getInstance("SHA1PRNG", "SUN");
    }

    @Test
    public void cleanBobAndAlice_aliceVerificationIsTrue_verificationsByKeyPairAreTrue() throws Exception {
        CoinFlipClient alice = new CoinFlipClient(random);
        CoinFlipClient bob = new CoinFlipClient(random);

        alice.assignPQ(p, q);
        bob.assignPQ(p, q);

        List<String> aliceCoin = alice.coin();
        String bobsPick = bob.pick(aliceCoin);

        String aliceEncodedPick = alice.decodePick(bobsPick);
        String coinFlipResult = bob.decodePick(aliceEncodedPick);

        System.out.println("CoinFlip Result is: " + new String(Hex.decode(coinFlipResult)));
        System.out.println("Alice random string verification: " + alice.verify(coinFlipResult));
        System.out.println("Alice Verification with Bobs Keypair: " + alice.verifyByKeyPair(bob.revealKeyPair()));
        System.out.println("Bob Verification with Alice' Keypair: " + bob.verifyByKeyPair(alice.revealKeyPair()));

        assertThat(alice.verify(coinFlipResult)).isTrue();
        assertThat(alice.verifyByKeyPair(bob.revealKeyPair())).isTrue();
        assertThat(bob.verifyByKeyPair(alice.revealKeyPair())).isTrue();
    }

    @Test
    public void simulateCheatingBob_aliceVerificationIsFalse_aliceVerificationWithKeyPairIsFalse() throws Exception {
        CoinFlipClient alice = new CoinFlipClient(random);
        CoinFlipClient bob = new CoinFlipClient(random);

        RandomStringGenerator stringGen = new RandomStringGenerator(random);

        alice.assignPQ(p, q);
        bob.assignPQ(p, q);

        List<String> aliceCoin = alice.coin();
        String bobsPick = bob.pick(aliceCoin);

        String aliceEncodedPick = alice.decodePick(bobsPick);

        // simulate a cheating bob. he tries to guess the random string and push a fixed result.
        String fakeResult = "heads_" + stringGen.randomString(20);
        String coinFlipResult = Hex.toHexString(fakeResult.getBytes());

        System.out.println("CoinFlip Result is: " + new String(Hex.decode(coinFlipResult)));
        System.out.println("Alice random string verification: " + alice.verify(coinFlipResult));
        System.out.println("Alice Verification with Bobs Keypair: " + alice.verifyByKeyPair(bob.revealKeyPair()));

        assertThat(alice.verify(coinFlipResult)).isFalse();
        assertThat(alice.verifyByKeyPair(bob.revealKeyPair())).isFalse();
    }

    @Test
    public void simulateCheatingAliceWithFakeCoin_bobVerificationIsFalse() throws Exception {
        CoinFlipClient alice = new CoinFlipClient(random);
        CoinFlipClient bob = new CoinFlipClient(random);

        // simulate fake coin with two heads from alice.
        RandomStringGenerator stringGen = new RandomStringGenerator(random);
        String heads = "heads_" + stringGen.randomString(20);
        String heads2 = "heads_" + stringGen.randomString(20);

        alice.assignPQ(p, q);
        bob.assignPQ(p, q);

        AsymmetricCipherKeyPair aliceKeyPair = alice.revealKeyPair();
        SRAEngine engine = new SRAEngine();
        engine.init(true, aliceKeyPair.getPublic());

        byte[] heads1enc = engine.processBlock(heads.getBytes(), 0, heads.getBytes().length);
        byte[] heads2enc = engine.processBlock(heads2.getBytes(), 0, heads2.getBytes().length);

        List<String> fakeCoin = Lists.newArrayList(Hex.toHexString(heads1enc), Hex.toHexString(heads2enc));
        List<String> aliceCoin = alice.coin();
        String bobsPick = bob.pick(fakeCoin);

        String aliceEncodedPick = alice.decodePick(bobsPick);
        String coinFlipResult = bob.decodePick(aliceEncodedPick);

        System.out.println("CoinFlip Result is: " + new String(Hex.decode(coinFlipResult)));
        System.out.println("Bob Verification with Alice' Keypair: " + bob.verifyByKeyPair(alice.revealKeyPair()));

        assertThat(bob.verifyByKeyPair(alice.revealKeyPair())).isFalse();
    }
}
