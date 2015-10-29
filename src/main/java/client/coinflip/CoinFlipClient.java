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

    private final SecureRandom random;

    private RandomStringGenerator generator;
    private String heads;
    private String tails;
    private boolean flipper = true;

    private SRAEngine engine;
    private AsymmetricCipherKeyPair keyPair;

    private AliceTestParameters aliceTest = null;
    private BobTestParameters bobTest = null;

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
        this.aliceTest = new AliceTestParameters();

        this.engine.init(true, keyPair.getPublic());

        String headsDecrypt = Hex.toHexString(this.engine.processBlock(this.heads.getBytes(), 0, this.heads.getBytes().length));
        String tailsDecrypt = Hex.toHexString(this.engine.processBlock(this.tails.getBytes(), 0, this.tails.getBytes().length));

        List<String> messages = Lists.newArrayList(headsDecrypt, tailsDecrypt);
        Collections.shuffle(messages);

        return messages;
    }

    //TODO: Stupid client, as he always picks the first input for now.
    public String pick(List<String> coin) {
        this.bobTest = new BobTestParameters();
        this.engine.init(true, keyPair.getPublic());
        byte[] pick = Hex.decode(coin.get(0));
        String pickString = Hex.toHexString(this.engine.processBlock(pick, 0, pick.length));

        this.bobTest.bobsPick = pickString;
        this.bobTest.aliceCoin = Lists.newArrayList(coin);

        return pickString;
    }

    public String decodePick(String pick) {
        this.engine.init(false, keyPair.getPrivate());

        byte[] decode = Hex.decode(pick);
        byte[] decodedPick = this.engine.processBlock(decode, 0, decode.length);

        if (this.flipper) {
            this.bobTest.aliceDecryption = pick;
        } else {
            this.aliceTest.bobEncryptedPick = pick;
        }

        return Hex.toHexString(decodedPick);
    }

    public boolean verify(String result) {
        byte[] decode = Hex.decode(result);
        String s = new String(decode);
        return s.equals(this.heads) || s.equals(this.tails);
    }

    public boolean verifyByKeyPair(AsymmetricCipherKeyPair other) {
        if (!this.flipper) {
            // der alice-fall

            // ich entschlüssele mit bobs private key und meinem private key
            // die von bob empfangene nachricht, und die muss eine von meinen sein.
            this.engine.init(false, other.getPrivate());
            byte[] data = Hex.decode(this.aliceTest.bobEncryptedPick);
            byte[] bobdecrypted = this.engine.processBlock(data, 0, data.length);

            this.engine.init(false, keyPair.getPrivate());
            byte[] finalDecrypted = this.engine.processBlock(bobdecrypted, 0, bobdecrypted.length);
            String s = new String(finalDecrypted);

            boolean check1 =  s.equals(this.heads) || s.equals(this.tails);

            // Alice muss prüfen, ob das, was sie im letzten Schritt (zur Verifizierung des RandomStrings)
            // von Bob bekommt dem entspricht, was sie von Bob verschlüsselt als Pick im ersten Schritt
            // bekommen hat.
            return check1;
        }
        // der bob fall

        // bob kann seinen verschlüsselten pick mit alice private key entschlüsseln und schauen
        // ob das, was dabei heraus kommt wirklich das ist, was alice ihm zum entschlüsseln für das
        // finale ergebnis geschickt hat.
        byte[] decode = Hex.decode(this.bobTest.bobsPick);
        this.engine.init(false, other.getPrivate());
        byte[] block = this.engine.processBlock(decode, 0, decode.length);
        String referral = Hex.toHexString(block);

        return referral.equals(this.bobTest.aliceDecryption);
    }

    public AsymmetricCipherKeyPair revealKeyPair() {
        return keyPair;
    }

    private class AliceTestParameters {
        private String bobFinalResult;
        private String bobEncryptedPick;
    }

    private class BobTestParameters {
        private String bobsPick;
        private String aliceDecryption;
        private List<String> aliceCoin;
    }
}
