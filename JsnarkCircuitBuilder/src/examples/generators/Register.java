/*******************************************************************************
 * Author: Seongho Park <shparkk95@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.MiMC7Gadget;

public class Register extends CircuitGenerator {

    /*  input */
    private Wire HashOut;
    /* witness */
    private Wire SK_id;

    /******************* BigInteger Values  ******************/
    public BigInteger sk_id;
    private MiMC7Gadget MiMC7;
    private int mode = 0 ;

    public Register(String circuitName, int mode){
        super(circuitName);
        this.mode = mode;
    }

    @Override
    protected void buildCircuit(){
        HashOut = createInputWire("hashin");
		SK_id = createProverWitnessWire("sk_id"); // voter private key

        MiMC7 = new MiMC7Gadget(new Wire[] {SK_id});
		Wire PK_id = MiMC7.getOutputWires()[0];

        addEqualityAssertion(PK_id, HashOut);
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        if (mode == 0) {
            circuitEvaluator.setWireValue(SK_id, new BigInteger("111111",10));
            circuitEvaluator.setWireValue(HashOut, new BigInteger("242e5dac01ff9bc696a866fbe0cebeb2ef3b836de1f9344f3bd8da5ddcfd1899", 16));
        }
        if (mode == 1) {
            circuitEvaluator.setWireValue(SK_id, sk_id);
        }
    }

    public static void main(String[] arga) throws Exception{
        Register register = new Register("Register", 0);
        register.generateCircuit();
        register.evalCircuit();
        register.prepFiles();
        register.runLibsnarksetup();
        register.runLibsnarkproof();
    }
}
