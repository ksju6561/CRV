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


public class SimpleCircuitGenerator_vote_ajitai_HO extends CircuitGenerator {

	public static int mode = 0;
	/********************* INPUT ***************************/
	// input_s
	// pk_e
	// leafWires
	/********************* OUTPUT ***************************/
	// PK_ID
	// sn
	// rt
	/********************* Witness ***************************/
	// SK_id
	// intermediateHasheWires
	// directionSelector

	/********************* Vote Msg and random ***************************/
	private Wire[] pp;
	private Wire[] E_id;

	private Wire[] SK_id;
	private Wire[] EK_id;
	private Wire candidate;

	private Wire PK_id;
	/********************* Register *****************************/
	// private Wire[] real;
	// private Wire s;
	// private Wire r;
	/********************* MerkleTree ***************************/
	// private Wire[] publicRootWires;
	private Wire[] intermediateHasheWires;
	private Wire directionSelector;

	private Wire randomizedEnc;
	/********************* Setup ***************************/
	public static BigInteger G;
	public static BigInteger grho;
	public static BigInteger rho;
	public static BigInteger[] pubp;

	/********************* Register **************************/
	public static BigInteger[] sk_id;
	public static BigInteger[] e_id;
	public static BigInteger[] pk_id;
	public static BigInteger[] ek_id;
	public static BigInteger[] PK_list;
	public static BigInteger[] PK_DB;
	public static BigInteger[] S;
	public static BigInteger[] T;

	/********************* Vote *****************************/
	public static BigInteger msg;
	public static BigInteger V;
	public static BigInteger W;
	public static BigInteger[] sn;
	public static BigInteger[] vct;

	private int num_of_elector = 64; // 2^6
	public static int x = 128;
	private int leafNumOfWords = 8;
	private int list_size = 1024;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;

	private MerkleTreePathGadget merkleTreeGadget;

	public BigInteger ReadCRS() {
		System.out.println("reading CRS");
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
				// System.out.println(i + "\t " + line);
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
		G = pubp[0];
		grho = pubp[1];
		System.out.println("reading CRS done");

		return rho;
	}

	public SimpleCircuitGenerator_vote_ajitai_HO(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
		this.num_of_elector = 64; // 2^6
		this.leafNumOfWords = 8;
		this.leafWordBitWidth = 256;
		this.list_size = 1024;
		this.hashDigestDimension = SubsetSumHashGadget.DIMENSION;

	}

	public Wire power(Wire input, Wire exp) {
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

	public BigInteger concat(BigInteger e, BigInteger n) {
		String a = String.valueOf(e);
		String b = String.valueOf(n);

		String val = a + b;

		BigInteger myval = new BigInteger(val);
		return myval;
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

	public BigInteger getSHA256(BigInteger m) {
		BigInteger result = BigInteger.ZERO;

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

	@Override
	protected void buildCircuit() {
		pp = createInputWireArray(2, "PP");

		E_id = createInputWireArray(leafNumOfWords, "e_id"); // 투표 번호

		SK_id = createProverWitnessWireArray(leafNumOfWords, "sk_id"); // voter private key

		candidate = createProverWitnessWire("candidate"); // 후보자
		
		EK_id = createProverWitnessWireArray(2, "ek_id"); // S = G ^ s , T = (S ^ rho) * (G ^ real)

		randomizedEnc = createProverWitnessWire("r");

		directionSelector = createProverWitnessWire("Direction selector");
		
		Wire[] skBits = new WireArray(SK_id).getBits(leafWordBitWidth).asArray();
        SubsetSumHashGadget subsetSumGadget = new SubsetSumHashGadget(skBits, false);
        Wire[] PK_id = subsetSumGadget.getOutputWires();
		
		// Wire[] sn_input = Util.concat(E_id, SK_id); // 8 8 일때 32 
		Wire[] sn_input = Util.concat(Util.concat(E_id, SK_id), EK_id); //sn = H(E_ID||SK_ID||EK_ID)
		//32 * 8 + 32 * 8 + 256 * 2
		// System.out.println("sn");
		Wire[] snBits = new WireArray(sn_input).getBits(leafWordBitWidth).asArray();
		//System.out.println("WW:"+snBits.length);
		SubsetSumHashGadget subsetSumGadget2 = new SubsetSumHashGadget(snBits, false);
		// 1111 1111 1111 1111 1111 1111 1111 111
		Wire[] snout = subsetSumGadget2.getOutputWires();
		makeOutputArray(snout, "sn");

        //makeOutputArray(PK_id, "PK_id");
		// System.out.println("pk_id");
		
		Wire[] ekpk = Util.concat(EK_id, PK_id); 
	
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");

		merkleTreeGadget = new MerkleTreePathGadget(directionSelector, ekpk, intermediateHasheWires, 254, treeHeight);
		Wire[] actualRoot = merkleTreeGadget.getOutputWires();

		// for (int i = 0; i < actualRoot.length; i++) {
		// 	actualRoot[i] = actualRoot[i];
		// }

		makeOutputArray(actualRoot, "Computed Root");

		Wire[] VCT = new Wire[2];

		VCT[0] = (power(pp[0], randomizedEnc)).mul(power(EK_id[0], candidate)); // V = (G ^ r) * (S ^ m)
		VCT[1] = power(EK_id[1], candidate).mul(power(pp[1], randomizedEnc));
		// }

		makeOutputArray(VCT, "vct");

	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		if (mode == 0) {
			int i = 0;
			circuitEvaluator.setWireValue(pp[0], Util.nextRandomBigInteger(256));
			circuitEvaluator.setWireValue(pp[1], Util.nextRandomBigInteger(256));
			
			for (i = 0; i < leafNumOfWords; i++) { // 8 66 ~ 81 //람다 = 256
				circuitEvaluator.setWireValue(E_id[i], Util.nextRandomBigInteger(32));
				circuitEvaluator.setWireValue(SK_id[i], Util.nextRandomBigInteger(32));
			}
			
			circuitEvaluator.setWireValue(candidate, Util.nextRandomBigInteger(6));
			
			for (i = 0; i < 2; i++) {
				circuitEvaluator.setWireValue(EK_id[i], Util.nextRandomBigInteger(256));
			}

			circuitEvaluator.setWireValue(randomizedEnc, Util.nextRandomBigInteger(1));

			circuitEvaluator.setWireValue(directionSelector, Util.nextRandomBigInteger(16)); //5742
			for (i = 0; i < hashDigestDimension * treeHeight; i++) { // 3 * 16 5743 ~ 5790
				circuitEvaluator.setWireValue(intermediateHasheWires[i], i);
			}
			
			//circuitEvaluator.setWireValue(randomizedEnc, Util.nextRandomBigInteger(256));
		} 
		else if (mode == 1) {
			int i = 0;
			circuitEvaluator.setWireValue(pp[0], G);
			circuitEvaluator.setWireValue(pp[1], grho);
			
			for (i = 0; i < leafNumOfWords; i++) { // 8 66 ~ 81
				circuitEvaluator.setWireValue(E_id[i], e_id[i]);
				circuitEvaluator.setWireValue(SK_id[i], sk_id[i]);
			}

			circuitEvaluator.setWireValue(candidate, msg);
			
			for (i = 0; i < 2; i++) {
				circuitEvaluator.setWireValue(EK_id[i], ek_id[i]);
			}
			circuitEvaluator.setWireValue(randomizedEnc, Util.nextRandomBigInteger(1));
			circuitEvaluator.setWireValue(directionSelector, Util.nextRandomBigInteger(16)); // 5742

			for (i = 0; i < hashDigestDimension * treeHeight; i++) { // 3 * 16 5743 ~ 5790
				circuitEvaluator.setWireValue(intermediateHasheWires[i], i);
			}
			
			//circuitEvaluator.setWireValue(randomizedEnc, pk_id);
		}

	}

	public void init_DB() {

		PK_list = new BigInteger[list_size];
		for (int i = 0; i < list_size; i++)
			PK_list[i] = BigInteger.ZERO;
		PK_DB = new BigInteger[leafNumOfWords];
		ek_id = new BigInteger[2];
		for (int i = 0; i < 2; i++)
			ek_id[i] = Util.nextRandomBigInteger(256);

	}

	public boolean Register(int i) {
		sk_id = new BigInteger[leafNumOfWords];
		boolean success = true;
		for (int j = 0; j < leafNumOfWords; j++)
			sk_id[j] = Util.nextRandomBigInteger(32);
		// BigInteger pk_id = getSHA256(sk_id);

		SimpleCircuitGenerator_register register = new SimpleCircuitGenerator_register("register");
		register.generateCircuit();
		BigInteger pk_id = register.snark(i, sk_id);
		register.runLibsnarkVerify(i);
		System.out.println("RegisterVerify");

		// BigInteger real = Util.nextRandomBigInteger(1);
		BigInteger real = BigInteger.ONE;
		BigInteger s = Util.nextRandomBigInteger(256);
		BigInteger r = Util.nextRandomBigInteger(256);
		BigInteger S = G.modPow(s, Config.FIELD_PRIME);
		BigInteger T = (S.modPow(rho, Config.FIELD_PRIME)).multiply(G.modPow(real, Config.FIELD_PRIME))
				.mod(Config.FIELD_PRIME);
		BigInteger R1 = S.modPow(r, Config.FIELD_PRIME);
		BigInteger R2 = G.modPow(r, Config.FIELD_PRIME);
		ek_id[0] = S;
		ek_id[1] = T;
		// for (int j = 0; j < list_size - 3; j += 3) {
		// 	if ((PK_list[j].equals(ek_id[i]) == true) && PK_list[j + 1].equals(ek_id[i + num_of_voter]) == true
		// 			&& PK_list[j + 2].equals(pk_id) == true) {
		// 		success = false;
		// 		break;
		// 	} else {
		// 		PK_list[j] = ek_id[i];
		// 		PK_list[j + 1] = ek_id[i + num_of_voter];
		// 		PK_list[j + 2] = pk_id;
		// 	}
		// }
		/// 이렇게 pkdb한번 더 체크해서 추가하던지

		BigInteger C = Util.nextRandomBigInteger(256);
		BigInteger K = r.add(C.multiply(rho));
		BigInteger SpowK = S.modPow(K, Config.FIELD_PRIME);
		BigInteger TdivG = BigInteger.ONE;
		if (real.equals(BigInteger.ONE) == true)
			TdivG = T.multiply(G.modInverse(Config.FIELD_PRIME)).mod(Config.FIELD_PRIME);
		else
			TdivG = T;
		if (SpowK.equals((TdivG.modPow(C, Config.FIELD_PRIME)).multiply(R1).mod(Config.FIELD_PRIME)) == false) {
			System.out.print(i + "\t");
			System.out.print(real + "\t");
			// System.out.print(SpowK + "\t" );
			// System.out.print(T[i] + "\t");
			// System.out.print(TdivG + "\t");
			// System.out.println((TdivG.modPow(C[i],
			// Config.FIELD_PRIME)).multiply(R1[i]).mod(Config.FIELD_PRIME));
			success = false;
		}
		BigInteger GpowR = G.modPow(rho, Config.FIELD_PRIME);
		if (G.modPow(K, Config.FIELD_PRIME)
				.equals((GpowR.modPow(C, Config.FIELD_PRIME)).multiply(R2).mod(Config.FIELD_PRIME)) == false) {
			System.out.println("second");
			System.out.print(i + "\t");
			// System.out.print(G.modPow(K[i], Config.FIELD_PRIME) + "\t");
			// System.out.print((GpowR.modPow(C[i],
			// Config.FIELD_PRIME)).multiply(R2[i]).mod(Config.FIELD_PRIME) + "\t");

			success = false;
		}

		return success;
	}

	public void Vote(int i) {
		// V = new BigInteger[num_of_elector];
		// W = new BigInteger[num_of_elector];
		vct = new BigInteger[2];
		BigInteger r = Util.nextRandomBigInteger(1);
		// sn = new BigInteger[leafNumOfWords];

		// for (int j = 0; j < leafNumOfWords; j++){
		// 	// System.out.println(j + "\ne_id : " + e_id[j] + "\nsk_id : " + sk_id[j] + "\nek_id : " + ek_id[i] + "\n");
		// 	// sn[j] = getSHA256(concat(e_id[j], sk_id[j]));
		// 	sn[j] = getSHA256(concat(concat(e_id[j], sk_id[j]), ek_id[0]));
		// }
		/// rt, path <- membershipcheck(ek_id, pk_id)
		msg = Util.nextRandomBigInteger(6);
		// m[v.intValue()].add(BigInteger.ONE);
		// for(int j = 0 ; j < num_of_elector; j++)
		// {
		vct[0] = G.modPow(r, Config.FIELD_PRIME).multiply((ek_id[0].modPow(msg, Config.FIELD_PRIME)))
				.mod(Config.FIELD_PRIME);
		vct[1] = G.modPow((rho.multiply(r)), Config.FIELD_PRIME)
				.multiply((ek_id[1].modPow(msg, Config.FIELD_PRIME))).mod(Config.FIELD_PRIME);
		// }
		try {
			File file = new File("./datafiles/" + circuitName + "_VCT" + i + ".dat");

			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file));

			if (file.isFile() && file.canWrite()) {

				bufferedWriter.write(vct[0].toString());
				bufferedWriter.newLine();
				bufferedWriter.write(vct[1].toString());

				bufferedWriter.close();
			}
		} catch (IOException e) {
			System.out.println(e);
		}
		try {
			File file1 = new File("./datafiles/" + "vote" + ".txt");

			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file1, true));

			PrintWriter pw = new PrintWriter(bufferedWriter, true);
			pw.write(i + "\t" + msg.toString() + "\n");
			pw.flush();
			pw.close();
		} catch (IOException e) {
			System.out.println(e);
		}
		// return msg;
	}
	
	public void setup(){
		mode = 0;
		SimpleCircuitGenerator_vote_ajitai_HO generator = new SimpleCircuitGenerator_vote_ajitai_HO("vote", 16);
		rho = generator.ReadCRS();
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		System.out.println("Hello Run Libsnark Setup");
		generator.runLibsnarksetup(0);
		generator.init_DB();
		
		mode = 1;
	}

	public void run(int i) {
		// mode = 1;
		SimpleCircuitGenerator_vote_ajitai_HO generator = new SimpleCircuitGenerator_vote_ajitai_HO("vote", 16);
		rho = generator.ReadCRS();
		generator.generateCircuit();
		boolean reg = generator.Register(i);
		if (reg == false)
			return;
		generator.Vote(i);
		System.out.println("voter no : " + i + "\t" + msg);

		// generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();

		System.out.println("Hello Run Libsnark");
		generator.runLibsnarkproof(i);
		generator.runLibsnarkVerify(i);

	}

	public static void main(String[] args) throws Exception {
		
		boolean reg;
		mode = 0;
		SimpleCircuitGenerator_vote_ajitai_HO generator = new SimpleCircuitGenerator_vote_ajitai_HO("vote",
				16);
		
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		System.out.println("Hello Run Libsnark Setup");
		generator.runLibsnarksetup(0);
		
		generator.init_DB();
		rho = generator.ReadCRS();
		
		mode = 1;
		for (int i = 1; i <= 10; i++) {
			reg = generator.Register(i);
			// System.out.println(reg);
			if (reg == false)
				return;
			
			generator.Vote(i);

			System.out.println("voter no : " + i + "\t" + msg);
			
			// generator.generateCircuit();
			generator.evalCircuit();
			generator.prepFiles();

			System.out.println("Hello Run Libsnark");
			generator.runLibsnarkproof(i);
			generator.runLibsnarkVerify(i);
		}
		
	}

}
