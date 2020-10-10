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


public class voter extends CircuitGenerator {
    public static int param;
    public BigInteger G;
    public BigInteger[] pp;
    public BigInteger[] PK_VD;
    private int leafNumOfWords = 8;
    private int leafWordBitWidth = 32;
    private BigInteger[] SK;
    private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;
    private Wire[] SK_id;
    public static int mode;
    //public Wire PK_id;

    public voter(String circuitName, int securityparameter, BigInteger G, int mode) {
        super(circuitName);
        this.param = securityparameter;
        this.G = G;
        this.mode = mode;
        // TODO Auto-generated constructor stub
    }
    
    private void setup() {
            PK_VD = new BigInteger[2];
            // pp = new BigInteger[3];
            // SK = new BigInteger[2];
            pp = new BigInteger[2];
            SK = new BigInteger[1];
            BigInteger rho = Util.nextRandomBigInteger(param);
            BigInteger U = G.modPow(rho, Config.FIELD_PRIME);
            pp[0] = G;
            pp[1] = U;
            // pp[2] = PK_enc;
            PK_VD[0] = G;
            PK_VD[1] = U;
            SK[0] = rho;
            // SK[1] = SK_enc;
        
        
    }
    @Override
    protected void buildCircuit() {
        
        SK_id = createProverWitnessWireArray(leafNumOfWords, "sk_id");
        Wire[] skBits = new WireArray(SK_id).getBits(leafWordBitWidth).asArray();
        SubsetSumHashGadget subsetSumGadget = new SubsetSumHashGadget(skBits, false);
        Wire[] PK_id = subsetSumGadget.getOutputWires();
        makeOutputArray(PK_id, "PK_id");

    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        // TODO Auto-generated method stub
        if(mode == 0)
        for (int i = 0; i < leafNumOfWords; i++) { // 8 66 ~ 81 //람다 = 256
            evaluator.setWireValue(SK_id[i], Util.nextRandomBigInteger(32));
        }
        else if  (mode == 1){
            for (int i = 0; i < leafNumOfWords; i++) { // 8 66 ~ 81 //람다 = 256
                evaluator.setWireValue(SK_id[i], Util.nextRandomBigInteger(32));
            }
        }
    }
    
    public static void main(String[] args) throws Exception{
        BigInteger G = SimpleCircuitGenerator_vote_0923.Generator();
		voter voter = new voter("voter", param, G, 0);
        voter.generateCircuit();
        voter.evalCircuit();
        voter.prepFiles();
        System.out.println("Run SETUP");
        voter.runLibsnarksetup(0);
        voter.setup();
        voter.evalCircuit();
        voter.prepFiles();
        voter.runLibsnarkproof(0);
        voter.runLibsnarkVerify(0);
    }
    
}
