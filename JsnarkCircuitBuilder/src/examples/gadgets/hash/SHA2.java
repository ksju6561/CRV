package examples.gadgets.hash;

import java.math.BigInteger;
import java.security.MessageDigest;

public class SHA2 {
    public static BigInteger getSHA256(BigInteger input) {

        BigInteger toReturn = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            digest.update(input.toByteArray());
            toReturn = new BigInteger(1, digest.digest());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return toReturn;
    }
}