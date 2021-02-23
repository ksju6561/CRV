/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators;

import java.math.BigInteger;
import java.util.Random;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
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

public class SimpleCircuitGenerator_tally extends CircuitGenerator {

    public static int mode = 0;
    public static int num_of_voter = 128;
    private int num_of_elector = 64;
    private int leafNumOfWords = 8;
    private int leafWordBitWidth = 32;
    private int treeHeight;
    private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;
    /****************************** Inputs ***********************/
    private Wire[] VCT;
    private Wire[] pp;
    private Wire M;

    private BigInteger R;

    /****************************** Witness ************************/
    private Wire sk;

    public static BigInteger[] pubp;
    public static BigInteger rho;
    public static BigInteger[] vct;
    public static BigInteger[] e_id;

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

    public SimpleCircuitGenerator_tally(String circuitName) {
        super(circuitName);
        // this.G = G;
    }

    @Override
    protected void buildCircuit() {
        pp = createInputWireArray(2, "pp");

        VCT = createInputWireArray(2, "VCT");

        M = createInputWire("msg");

        sk = createProverWitnessWire("rho");

        if (VCT[1].equals((power(VCT[0], sk).mul((power(pp[0], M))))) == false)
            return;
        if (pp[1].equals(power(pp[0], sk)) == false)
            return;

    }

    @Override
    public void generateSampleInput(CircuitEvaluator evaluator) {
        if (mode == 0) {
            evaluator.setWireValue(pp[0], Util.nextRandomBigInteger(256));
            evaluator.setWireValue(pp[1], Util.nextRandomBigInteger(256));

            for (int i = 0; i < 2; i++) {
                evaluator.setWireValue(VCT[i], Util.nextRandomBigInteger(256));

            }
            evaluator.setWireValue(M, Util.nextRandomBigInteger(6));
            evaluator.setWireValue(sk, Util.nextRandomBigInteger(256));
        }
        if (mode == 1) {
            evaluator.setWireValue(pp[0], pubp[0]);
            evaluator.setWireValue(pp[1], pubp[1]);

            for (int i = 0; i < 2; i++) {
                evaluator.setWireValue(VCT[i], vct[i]);
            }
            evaluator.setWireValue(M, R);
            evaluator.setWireValue(sk, rho);
        }
    }

    public void ReadCRS() {
		pubp = new BigInteger[2];
		int i = 0;
		try {
            // 파일 객체 생성
            File file = new File("./datafiles/" + "PP.dat");
            // 입력 스트림 생성
            FileReader filereader = new FileReader(file);
            // 입력 버퍼 생성
            BufferedReader bufReader = new BufferedReader(filereader);
            String line = "";
            while ((line = bufReader.readLine()) != null) {
                //System.out.println(line);
				pubp[i] = new BigInteger(line);
                i++;
            }
            // .readLine()은 끝에 개행문자를 읽지 않는다.  
            filereader.close();
            bufReader.close();
        } catch (FileNotFoundException e) {
            // TODO: handle exception
        } catch (IOException e) {
            System.out.println(e);
        }
		
		try {
            // 파일 객체 생성
            File file = new File("./datafiles/" + "sk.dat");
            // 입력 스트림 생성
            FileReader filereader = new FileReader(file);
            // 입력 버퍼 생성
            BufferedReader bufReader = new BufferedReader(filereader);
			String line = "";
			while ((line = bufReader.readLine()) != null) {
				// System.out.println(line);
				rho = new BigInteger(line);
			}
            // .readLine()은 끝에 개행문자를 읽지 않는다.  
            filereader.close();
            bufReader.close();
        } catch (FileNotFoundException e) {
			System.out.println(e);
        } catch (IOException e) {
            System.out.println(e);
		}
		i=0;
		e_id = new BigInteger[leafNumOfWords];
		try {
            // 파일 객체 생성
            File file = new File("./datafiles/" + "e_id.dat");
            // 입력 스트림 생성
            FileReader filereader = new FileReader(file);
            // 입력 버퍼 생성
            BufferedReader bufReader = new BufferedReader(filereader);
			String line = "";
			while ((line = bufReader.readLine()) != null) {
				// System.out.println(line);
				e_id[i] = new BigInteger(line);
				i++;
			}
            // .readLine()은 끝에 개행문자를 읽지 않는다.  
            filereader.close();
            bufReader.close();
        } catch (FileNotFoundException e) {
			System.out.println(e);
        } catch (IOException e) {
            System.out.println(e);
        }
		// bb=?
	
    }

    public BigInteger Tally(int i) {
        int j = 0;
        vct = new BigInteger[2];
        try {
            // 파일 객체 생성
            File file = new File("./datafiles/" + "voting_ajitai16" + "_VCT" + i + ".dat");
            // 입력 스트림 생성
            FileReader filereader = new FileReader(file);
            // 입력 버퍼 생성
            BufferedReader bufReader = new BufferedReader(filereader);
            String line = "";
            while ((line = bufReader.readLine()) != null) {
                System.out.println(line);
                vct[j] = new BigInteger(line);
                j++;
            }
            // .readLine()은 끝에 개행문자를 읽지 않는다.
            
            bufReader.close();
            filereader.close();
        } catch (FileNotFoundException e) {
            // TODO: handle exception
            System.out.println(e);
        } catch (IOException e) {
            System.out.println(e);
        }
        R = BigInteger.ZERO;
        BigInteger V = vct[0];
        BigInteger W = vct[1];

        for (int m = 0 ; m < num_of_elector ; m++)
        {
            if (W.equals(
                    (V.modPow(rho, Config.FIELD_PRIME)).multiply((pubp[0].modPow(BigInteger.valueOf(m), Config.FIELD_PRIME))).mod(Config.FIELD_PRIME)) == true) {
                R = BigInteger.valueOf(m);
                break;
            }
        }
        System.out.println("VCT READED");
        try{
			File file1 = new File("./datafiles/" + circuitName + ".txt");

			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file1, true));
            
			PrintWriter pw = new PrintWriter(bufferedWriter, true);
			pw.write(i + "\t" + R.toString() + "\n");
			pw.flush();
            pw.close();
        }catch (IOException e) {
            System.out.println(e);
        }

        return R;
    }

    public void setup(){
        mode = 0;
        // SimpleCircuitGenerator_tally tally = new SimpleCircuitGenerator_tally("tally", 16);
        this.ReadCRS();
        this.generateCircuit();
        this.evalCircuit();
        this.prepFiles();
        System.out.println("tally setup");
        this.runLibsnarksetup(0);
        // tally.runLibsnark();
        // tally.runLibsnarkVerify();
        mode = 1;
	}

    public static void main(String[] args) throws Exception {
        mode = 0;
        SimpleCircuitGenerator_tally tally = new SimpleCircuitGenerator_tally("tally");
        tally.generateCircuit();
        tally.evalCircuit();
        tally.prepFiles();
        tally.runLibsnarksetup(0);
        tally.ReadCRS();
        // tally.runLibsnark();
        // tally.runLibsnarkVerify();
        mode = 1;
        for (int i = 1; i <= num_of_voter; i++) {
            BigInteger Msg = tally.Tally(i);
            System.out.println("voter no : " + i + "\t" + "tally output : " + Msg);
        }
            tally.evalCircuit();
            tally.prepFiles();
            System.out.println("runLibsnark");
            tally.runLibsnarkproof(num_of_voter);
            System.out.println("runLibsnarkverify");
            tally.runLibsnarkVerify(num_of_voter);
        
        
    }

}