package generator;

import java.security.SecureRandom;

public class RandomStringGenerator {
    private static final String POSSIBLE_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";

    private SecureRandom random;

    public RandomStringGenerator(SecureRandom random) {
        this.random = random;
    }

    public String randomString(int length) {
        char[] password = new char[length];

        char[] possibleCharacters = POSSIBLE_CHARACTERS.toCharArray();

        for (int i = 0; i < length; i++) {
            password[i] = possibleCharacters[random.nextInt(possibleCharacters.length)];
        }

        return new String(password);
    }

}
