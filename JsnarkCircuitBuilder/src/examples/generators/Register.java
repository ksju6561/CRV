/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SubsetSumHashGadget;

public class Register extends CircuitGenerator {

    /*  input */
    private Wire[][] pp;
    /* witness */
    private Wire[] SK_id;
    /* output */
    private Wire[] PK_id;

    private int leafNumOfWords = 8;
    private int leafWordBitWidth = 32;
    private SubsetSumHashGadget subsetSumHashGadget;

    public Register(String circuitName){
        super(circuitName);
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
        for(int i = 0 ; i < leafNumOfWords ; i++)
        circuitEvaluator.setWireValue(SK_id[i], Integer.MAX_VALUE);
    }
    
    public void setup()
    {
        this.generateCircuit();
        this.evalCircuit();
        this.prepFiles();
        this.runLibsnark();
    }

    public static void main(String[] arga) throws Exception{
        Register register = new Register("register");
        register.generateCircuit();
        register.evalCircuit();
        register.prepFiles();
        register.runLibsnark();
    }

}
