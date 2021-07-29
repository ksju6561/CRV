package examples.gadgets.hash;

import circuit.operations.Gadget;
import circuit.structure.Wire;
import org.ethereum.crypto.cryptohash.Keccak256;
import java.math.BigInteger;
import java.util.Arrays;

public class MiMC7Gadget extends Gadget {
    private Wire output;

    /**
     * MiMC specialized for Fr in ALT-BN128, in which the exponent is 7 and 91
     * rounds are used.
     */
    private static Keccak256 keccak256 = new Keccak256(); // Must declared before using _keccak256()
    private static String seedStr = "snplab_CRV_seed";
    private static BigInteger seed = _keccak256(seedStr.getBytes());
    private static int numRounds = 91;
    private static final BigInteger[] roundConstants;

    public MiMC7Gadget(Wire inputLeft, Wire inputRight, String... desc) {
        super(desc);

        output = Encrypt(inputLeft, inputRight).add(inputLeft).add(inputRight);
    }

    public MiMC7Gadget(Wire[] inputs, String... desc) {
        super(desc);

        if(inputs.length == 1)
        {
            output = Encrypt(inputs[0], inputs[0]).add(inputs[0]).add(inputs[0]);
        }
        else{
            Wire mimc7;
            output = inputs[0];
            for(int i=1; i<inputs.length; i++) {
                mimc7 = Encrypt(output, inputs[i]).add(output).add(inputs[i]);
                output = mimc7;
            }   
        }
    }


    static {
        roundConstants = new BigInteger[numRounds];
        roundConstants[0] = seed;
        for (int i = 1; i < numRounds; i++) {
            roundConstants[i] = _updateRoundConstant(roundConstants[i-1]);
        }
    }

    private Wire MiMC_round(Wire message, Wire key, BigInteger rc) {
        Wire xored = message.add(key).add(rc); // mod prime automatically
        
        Wire tmp = xored;
        for (int i=0; i<2; i++) {
            tmp = tmp.mul(tmp);
            xored = xored.mul(tmp);
        }
        return xored;
    }

    private Wire Encrypt(Wire message, Wire ek) {
        Wire result = message;
        Wire key = ek;
        // BigInteger roundConstant = seed;

        result = MiMC_round(result, key, BigInteger.ZERO);

        for (int i = 1; i < numRounds; i++) {
            // round_constant = _updateRoundConstant(round_constant);
            // roundConstant = roundConstants[i];
            result = MiMC_round(result, key, roundConstants[i]);
        }

        return result.add(key);

    }

    private static BigInteger _keccak256(byte[] inputs) {
        byte[] out = keccak256.digest(inputs);

        String hex_string = byteArrayToHexString(out).toLowerCase();
        BigInteger res = new BigInteger(hex_string, 16);
        return res;
    }

    private static byte[] adjustBytes(byte[] input, int length) {
        if (input.length >= length) { // restrict byte length
            byte[] restrictedByte = new byte[length];
            System.arraycopy(input, input.length - length, restrictedByte, 0, length);
            return restrictedByte;
        }
        // zero padding
        byte[] res = new byte[32];
        byte[] pad = new byte[32 - input.length];

        Arrays.fill(pad, (byte) 0);

        System.arraycopy(pad, 0, res, 0, pad.length);
        System.arraycopy(input, 0, res, pad.length, input.length);

        return res;
    }

    private static BigInteger _updateRoundConstant(BigInteger rc) {
        byte[] byteArray = rc.toByteArray();
        byte[] padding_byte = adjustBytes(byteArray, 32);

        return _keccak256(padding_byte);
    }

    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xff));
        }

        return sb.toString();
    }

    @Override
    public Wire[] getOutputWires() {
        return new Wire[] { output };
    }

}
