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
import circuit.structure.ConstantWire;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SHA256Gadget;
import examples.gadgets.hash.SubsetSumHashGadget;

public class Tally extends CircuitGenerator {
    /* INPUT */
    private Wire[][] pp;
    private Wire[][] VCT;
    private Wire[] candidate; //MAX = 2^6 * 2 ^ 16
    /* WITNESS */
    private Wire[] SK;

    private int leafNumofWords = 8;

    public Tally(String circuitName) {
        super(circuitName);
    }

    public Wire power(Wire input, Wire exp) {
		Wire zeroWire = createConstantWire(new BigInteger("0"));
		Wire oneWire = createConstantWire(new BigInteger("1"));
		Wire res = createConstantWire(new BigInteger("1"));
		int index = 0;

		Wire[] getBitExp = exp.getBitWires(256).asArray();
		for (int i = 0; i < 256; i++) {
			Wire tmp = input.sub(1);
			tmp = tmp.mul(getBitExp[i]);
			tmp = tmp.add(1);

			res = res.mul(tmp);

			exp = exp.shiftRight(1, 256);
			input = input.mul(input);
		}
		return res;
    }
    
    @Override
    protected void buildCircuit(){
        Wire oneWire = createConstantWire(new BigInteger("1"));
        pp = new Wire[2][];
        VCT = new Wire[2][];
        for(int i = 0 ; i < 2 ; i++){
            pp[i] = createInputWireArray(leafNumofWords, "pp" + Integer.toString(i));
            VCT[i] = createInputWireArray(leafNumofWords, "VCT" + Integer.toString(i));
        }
        candidate = createInputWireArray(2, "candidate");
        SK = createProverWitnessWireArray(leafNumofWords, "sk");
        //Wire[] msum = Util.concat(candidate[0], candidate[1]);
        for(int i = 0 ; i < leafNumofWords ; i++){
            for(int j = 0 ; j < 2 ; j++)
            if(VCT[1][i].isEqualTo((power(VCT[0][i], SK[i]).mul((power(pp[0][i], candidate[j]))))) == oneWire ){
                System.out.println("err 1, "+i);
                return ;
            }
            if(pp[1][i].isEqualTo(power(pp[0][i], SK[i])) == oneWire ){
                System.out.println("err 2, "+i);
                return ;
            }
        }
    }

    @Override
    public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        for(int i = 0 ; i < 2 ; i++){
			for(int j = 0 ; j < leafNumofWords ; j++){
                circuitEvaluator.setWireValue(pp[i][j], Integer.MAX_VALUE);
                circuitEvaluator.setWireValue(VCT[i][j], Integer.MAX_VALUE);
            }
            circuitEvaluator.setWireValue(candidate[i], Integer.MAX_VALUE);
        }

        for(int i = 0 ; i < leafNumofWords ; i++){
            circuitEvaluator.setWireValue(SK[i], Integer.MAX_VALUE);
        }
    }

    public static void main(String[] args) throws Exception{
        Tally tally = new Tally("tally");
        tally.generateCircuit();
        tally.evalCircuit();
        tally.prepFiles();
        tally.runLibsnark();
    }

}