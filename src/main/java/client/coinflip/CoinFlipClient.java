package client.coinflip;

import com.google.common.collect.Lists;
import generator.RandomStringGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SRAEngine;
import org.bouncycastle.crypto.generators.SRAKeyPairGenerator;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;

public class CoinFlipClient {
    private static final int RANDOM_STRING_LENGTH = 20;
    private static final String HEADS = "heads";
    private static final String TAILS = "tails";
    private static final String DELIMITER = "_";
    private static final int CERTAINTY = 80;

    private List<String> log = Lists.newArrayList();

    private final SecureRandom random;

    private RandomStringGenerator generator;
    private String heads;
    private String tails;
    private boolean flipper = true;

    private SRAEngine engine;
    private AsymmetricCipherKeyPair keyPair;

    public CoinFlipClient(SecureRandom random) {
        this.random = random;
        this.generator = new RandomStringGenerator(random);
        this.heads = HEADS + DELIMITER + generator.randomString(RANDOM_STRING_LENGTH);
        this.tails = TAILS + DELIMITER + generator.randomString(RANDOM_STRING_LENGTH);
        this.engine = new SRAEngine();
    }

    public void assignPQ(BigInteger p, BigInteger q) {
        SRAKeyPairGenerator keyPairGen = new SRAKeyPairGenerator();
        SRAKeyPairGenerator.SRAKeyGenerationParameters params = new SRAKeyPairGenerator.SRAKeyGenerationParameters(p, q, random, CERTAINTY);
        keyPairGen.init(params);
        keyPair = keyPairGen.generateKeyPair();
    }

    public List<String> coin() {
        this.flipper = false;
        this.engine.init(true, keyPair.getPublic());

        String headsDecrypt = Hex.toHexString(this.engine.processBlock(this.heads.getBytes(), 0, this.heads.getBytes().length));
        String tailsDecrypt = Hex.toHexString(this.engine.processBlock(this.tails.getBytes(), 0, this.tails.getBytes().length));

        List<String> messages = Lists.newArrayList(headsDecrypt, tailsDecrypt);
        Collections.shuffle(messages);

        return messages;
    }

    //TODO: Stupid client, as he always picks the first input for now.
    public String pick(List<String> coin) {
        this.engine.init(true, keyPair.getPublic());
        byte[] pick = Hex.decode(coin.get(0));

        return Hex.toHexString(this.engine.processBlock(pick, 0, pick.length));
    }

    public String decodePick(String pick) {
        this.engine.init(false, keyPair.getPrivate());

        byte[] decode = Hex.decode(pick);
        byte[] decodedPick = this.engine.processBlock(decode, 0, decode.length);

        this.log.add(pick);

        return Hex.toHexString(decodedPick);
    }

    public boolean verify(String result) {
        byte[] decode = Hex.decode(result);
        String s = new String(decode);
        return s.equals(this.heads) || s.equals(this.tails);
    }

    public boolean verifyByKeyPair(AsymmetricCipherKeyPair keyPair) {
        return true;
    }

    public AsymmetricCipherKeyPair revealKeyPair() {
        return keyPair;
    }
}
