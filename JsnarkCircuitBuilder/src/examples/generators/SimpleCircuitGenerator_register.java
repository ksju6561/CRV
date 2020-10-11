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


public class SimpleCircuitGenerator_register extends CircuitGenerator {
    public BigInteger G;
    private BigInteger rho;
    public BigInteger grho;
    public BigInteger[] pp;
    public BigInteger[] PK_VD;
    public BigInteger[] e_id;
    private BigInteger[] sk_id;
    private int leafNumOfWords = 8;
    private int leafWordBitWidth = 32;
    private BigInteger[] SK;

    private Wire[] SK_id;
    public static int mode;
    //public Wire PK_id;

    public SimpleCircuitGenerator_register(String circuitName) {
        super(circuitName);
		this.leafNumOfWords = 8;
		this.leafWordBitWidth = 32;
        // TODO Auto-generated constructor stub
    }
    public BigInteger getSHA256(BigInteger msg[]) {
		BigInteger result = BigInteger.ZERO;
		BigInteger m = BigInteger.ZERO;
		for (int i = 0; i < leafNumOfWords; i++)
			m = m.shiftLeft(8).add(msg[i]);
		MessageDigest mDigest;
		try {
			mDigest = MessageDigest.getInstance("SHA-256");
			mDigest.reset();
			mDigest.update(m.toByteArray());
			result = new BigInteger(1, mDigest.digest());
		} catch (Exception e) {

			e.printStackTrace();
		}
		return result;
	}
    public BigInteger ReadCRS() {
		System.out.println("register. reading CRS");
		pp = new BigInteger[2];
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
				pp[i] = new BigInteger(line);
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
        G = pp[0];
		grho = pp[1];
		
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
				//System.out.println(i + "\t " + line);
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
		
		System.out.println("register. reading CRS done");
        PK_VD = new BigInteger[2];
        PK_VD[0] = G;
        PK_VD[1] = grho;
        SK = new BigInteger[1];
        SK[0] = rho;
		return rho;
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
        System.out.println("mode : " + mode);
        // TODO Auto-generated method stub
        if (mode == 0) {
            for (int i = 0; i < leafNumOfWords; i++) { // 8 66 ~ 81 //람다 = 256
                evaluator.setWireValue(SK_id[i], Util.nextRandomBigInteger(32));
            }
        } else if (mode == 1) {
            for (int i = 0; i < leafNumOfWords; i++) { // 8 66 ~ 81 //람다 = 256
                //System.out.println(sk_id[i]);
                evaluator.setWireValue(SK_id[i], sk_id[i]);
            }
        }
    }

    public void setup()
    {
        SimpleCircuitGenerator_register voter = new SimpleCircuitGenerator_register("register");
        mode = 0;
        rho = voter.ReadCRS();
        voter.generateCircuit();
        voter.evalCircuit();
        voter.prepFiles();
        System.out.println("Run SETUP");
        voter.runLibsnarksetup(0);
        mode = 1;
    }

    public BigInteger snark(int n, BigInteger[] sk)
    {
        // SimpleCircuitGenerator_register voter = new SimpleCircuitGenerator_register("register");
        //this.generateCircuit();
        mode = 1;
        rho = this.ReadCRS();
        
        sk_id = new BigInteger[leafNumOfWords];
        for (int j = 0; j < leafNumOfWords; j++)
        {	sk_id[j] = sk[j];
            //System.out.println(sk_id[j]);   
        }
		BigInteger pk_id = getSHA256(sk_id);
        
        this.evalCircuit();
        this.prepFiles();
        this.runLibsnarkproof(n);
        System.out.println("asdf");
        // this.runLibsnarkVerify(n);

        return pk_id;
    }
    
    public static void main(String[] args) throws Exception{
        // BigInteger G = SimpleCircuitGenerator_vote_0923.Generator();
		SimpleCircuitGenerator_register voter = new SimpleCircuitGenerator_register("register");
        voter.generateCircuit();
        // voter.evalCircuit();
        // voter.prepFiles();
        // System.out.println("Run SETUP");
        // voter.runLibsnarksetup(0);
        voter.ReadCRS();
        BigInteger[] skid = new BigInteger[8];
        for(int i = 0 ; i < 8 ; i++)
        skid[i] = Util.nextRandomBigInteger(32);
        voter.snark(0, skid);
        voter.runLibsnarkVerify(0);
    }
    
}
