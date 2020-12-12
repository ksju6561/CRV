/*******************************************************************************
 * Author: Seongho Park <shparkk95@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
// import java.math.*;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.ConstantWire;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SHA256Gadget;
import examples.gadgets.hash.SubsetSumHashGadget;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupGeneratorGadget;
import examples.gadgets.diffieHellmanKeyExchange.ECGroupOperationGadget;


public class Tally extends CircuitGenerator {
    /* INPUT */
    private Wire G;
    private Wire U;
    private Wire V;
    private Wire W;
    private Wire[] msgsum; //MAX = 2^6 * 2 ^ 16
    /* WITNESS */
    private Wire SK;

    private int leafNumofWords = 8;
    private int leafWordBitWidth = 32;
    private int numofelector;
    private int msgsize;
    private int treeHeight;
    public static final int EXPONENT_BITWIDTH = 253; // in bits


    public Tally(String circuitName, int treeHeight, int numofelector) {
        super(circuitName);
        this.treeHeight = treeHeight;
        this.numofelector = numofelector;
    }

    public Wire[] expwire(Wire input){
		Wire zerobitWire = createConstantWire(new BigInteger("0")).getBitWires(1).get(0);
		Wire onebitWire = oneWire.getBitWires(1).get(0);
		Wire[] temp = input.getBitWires(EXPONENT_BITWIDTH-3).asArray();
		Wire[] output = new Wire[EXPONENT_BITWIDTH];
		output[0] = zeroWire;
		output[1] = zeroWire;
		output[2] = zeroWire;
		for(int i = 3 ; i < EXPONENT_BITWIDTH  ; i++)
			output[i] = temp[i-3];
		output[EXPONENT_BITWIDTH - 1] = oneWire;
		for(int i = 0 ; i < output.length ; i++){
			addBinaryAssertion(output[i], Integer.toString(i));
		}
		return output;
	}

    @Override
    protected void buildCircuit(){
        Wire oneWire = createConstantWire(new BigInteger("1"));
        Wire zeroWire = createConstantWire(BigInteger.ZERO);
        Wire wiretwo = createConstantWire(BigInteger.ONE);
        Wire o = oneWire.checkNonZero("zero?");
        G = createInputWire("G");
        U = createInputWire("U");
        V = createInputWire("V");
        W = createInputWire("W");
        msgsize = treeHeight * numofelector / Config.LOG2_FIELD_PRIME + 1;
        System.out.println(msgsize);
        msgsum = createInputWireArray(msgsize, "candidate");
        
        SK = createProverWitnessWire("sk");
        // Wire rho = new WireArray(SK).getBits(leafWordBitWidth).packAsBits(256, "rho");
        Wire[] skbits = expwire(SK);
        ECGroupGeneratorGadget dec2 = new ECGroupGeneratorGadget(G, skbits);
        Wire n = dec2.getOutputPublicValue();
        makeOutput(n, "n");
        makeOutput(U, "U");
        Wire out1 = n.sub(U, "assert1");

        addEqualityAssertion(out1, zeroWire, "assert1");
        // Wire temp = n.sub(U);
        
        // temp = temp.checkNonZero();
        // System.out.println(temp.isEqualTo(BigInteger.ZERO));
        // makeOutput(temp, "zero?");

        // if(temp.isEqualTo(zeroWire).equals(oneWire)){
        //     System.out.println("RHO IS VALID");
        // }
            // System.out.println(i);
        Wire[] Gtomsbits = new Wire[0];
        for(int i = 0 ; i < msgsize ; i++){
            Wire[] msg = msgsum[i].getBitWires(EXPONENT_BITWIDTH - 3).asArray();
            Wire[] msgbits = expwire(msg[i]);
            ECGroupGeneratorGadget makemsum = new ECGroupGeneratorGadget(G, msgbits);
            Wire Gtom = makemsum.getOutputPublicValue();
            Gtomsbits = Util.concat(Gtomsbits, Gtom.getBitWires(Config.LOG2_FIELD_PRIME).asArray());
        }
        Wire Gtom = new WireArray(Gtomsbits).packAsBits((Config.LOG2_FIELD_PRIME) * msgsize);
        Gtom = W;
        makeOutput(Gtom);
        ECGroupOperationGadget dec = new ECGroupOperationGadget(V, skbits, Gtom);
        Wire m = dec.getOutputPublicValue();
        makeOutput(m, "V^sk * G^M");
        // Wire[] msgbits = expwire(msg);
        
        
    
        
        // System.out.println("end" + i);
        
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        circuitEvaluator.setWireValue(G, new BigInteger("10398164868948269691505217409040279103932722394566360325611713252123766059173"));
        circuitEvaluator.setWireValue(U, new BigInteger("9091054082811332808408882460551019864591326367199559281300795799522407870087"));
        circuitEvaluator.setWireValue(V, new BigInteger("7767048000378549177581603936959002550151655261351310972029464155446562514954"));
        circuitEvaluator.setWireValue(W, new BigInteger("6141409309494266378265483028038598208198589142795463879598813571694701018988"));

        for(int i = 0 ; i < msgsize ; i++){
            circuitEvaluator.setWireValue(msgsum[i], Util.nextRandomBigInteger(250));
        }
        
        circuitEvaluator.setWireValue(SK, new BigInteger("828835783108031076797394912765253017541492695537107424735552520256055782312"));
        
             
    }

    public static void main(String[] args) throws Exception{
        Tally tally = new Tally("tally", 32, 64);
        tally.generateCircuit();
        tally.evalCircuit();
        tally.prepFiles();
        tally.runLibsnark();
    }

}