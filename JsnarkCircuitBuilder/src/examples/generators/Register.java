/*******************************************************************************
 * Author: Seongho Park <shparkk95@kookmin.ac.kr>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
import java.util.Random;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.PrintWriter;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SubsetSumHashGadget;

public class Register extends CircuitGenerator {

    /*  input */
    private Wire[][] PP;
    /* witness */
    private Wire[] SK_id;
    /* output */
    private Wire[] PK_id;

    /******************* BigInteger Values  ******************/
    public BigInteger[] sk_id;

    private int leafNumOfWords = 8;
    private int leafWordBitWidth = 32;
    private SubsetSumHashGadget subsetSumHashGadget;
    private int mode = 0 ;

    public Register(String circuitName, int mode){
        super(circuitName);
        this.mode = mode;
    }

    @Override
    protected void buildCircuit(){
		SK_id = createProverWitnessWireArray(leafNumOfWords, "sk_id"); // voter private key
        Wire[] skBits = new WireArray(SK_id).getBits(leafWordBitWidth).asArray();
		// System.out.println("ww : " + skBits.length);
        subsetSumHashGadget = new SubsetSumHashGadget(skBits, false);
		Wire[] PK_id = subsetSumHashGadget.getOutputWires();
		makeOutputArray(PK_id, "PK_id");
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        if (mode == 0) {
            for (int i = 0; i < leafNumOfWords; i++)
                circuitEvaluator.setWireValue(SK_id[i], Integer.MAX_VALUE);
        }
        if (mode == 1) {
            for (int i = 0; i < leafNumOfWords; i++)
                circuitEvaluator.setWireValue(SK_id[i], sk_id[i]);
        }
    }
    
    public void setup()
    {
        this.generateCircuit();
        this.evalCircuit();
        this.prepFiles();
        this.runLibsnarksetup(0);
    }

    public static void main(String[] arga) throws Exception{
        Register register = new Register("register", 0);
        register.generateCircuit();
        register.evalCircuit();
        register.prepFiles();
        register.runLibsnarksetup(0);
        register.runLibsnarkproof(0);
        register.runLibsnarkVerify(0);
    }

}
