/*******************************************************************************
 * Author: Jaekyoung Choi <cjk2889@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
import java.util.Arrays;

import util.Util;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.diffieHellmanKeyExchange.ECDHKeyExchangeGadget;

public class jk extends CircuitGenerator {

    private Wire[] secExpBits;

    // Will assume the parameterization used in the test files ~ 80-bits
    // security
    public static final int EXPONENT_BITWIDTH = 253; // in bits

    public jk(String circuitName) {
        super(circuitName);
    }

    @Override
    protected void buildCircuit() {

        // The secret exponent is a private input by the prover
        secExpBits = createProverWitnessWireArray(EXPONENT_BITWIDTH, "SecretExponent");
        for (int i = 0; i < EXPONENT_BITWIDTH; i++) {
            addBinaryAssertion(secExpBits[i]); // verify all bits are binary
        }

        Wire g = createConstantWire(
                new BigInteger("16377448892084713529161739182205318095580119111576802375181616547062197291263"));
        ;
        Wire h = createConstantWire(
                new BigInteger("8252578783913909531884765397785803733246236629821369091076513527284845891757"));

        ECDHKeyExchangeGadget exchange = new ECDHKeyExchangeGadget(g, h, secExpBits);

        // Output g^s
        Wire[] g_to_s = exchange.getOutputWires();
        makeOutputArray(g_to_s, "DH Key Exchange Output");

    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        for (int i = 3; i < EXPONENT_BITWIDTH - 1; i++) {
            circuitEvaluator.setWireValue(secExpBits[i], Util.nextRandomBigInteger(1));
        }
        circuitEvaluator.setWireValue(secExpBits[0], 0);
        circuitEvaluator.setWireValue(secExpBits[1], 0);
        circuitEvaluator.setWireValue(secExpBits[2], 0);
        circuitEvaluator.setWireValue(secExpBits[EXPONENT_BITWIDTH - 1], 1);

    }

    public static void main(String[] args) throws Exception {

        jk generator = new jk("ECDHtestcircuit");
        generator.generateCircuit();
        generator.evalCircuit();
        generator.prepFiles();
        generator.runLibsnark();
    }

}
