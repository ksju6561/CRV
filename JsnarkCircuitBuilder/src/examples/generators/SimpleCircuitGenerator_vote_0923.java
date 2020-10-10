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

public class SimpleCircuitGenerator_vote_0923 extends CircuitGenerator {

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

	private Wire[] PK_id;
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
	public static BigInteger m;
	public static BigInteger V;
	public static BigInteger W;
	public static BigInteger[] sn;
	public static BigInteger[] vct;

	private int num_of_elector = 64; // 2^6
	public static int num_of_voter = 128;
	private int leafNumOfWords = 8;
	private int list_size = 1024;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	private int hashDigestDimension = SubsetSumHashGadget.DIMENSION;

	private MerkleTreePathGadget merkleTreeGadget;

	public SimpleCircuitGenerator_vote_0923(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
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

	private static BigInteger GCD(BigInteger a, BigInteger b) {
		if (b.signum() == 0) {
			return a;
		}
		return GCD(b, a.mod(b));
	}

	public static BigInteger Generator() {
		BigInteger g, b = Config.FIELD_PRIME;

		g = Util.nextRandomBigInteger(256);
		while ((GCD(g, b).compareTo(BigInteger.ONE) != 0) && (g.compareTo(Config.FIELD_PRIME)) > 0) {

			g = Util.nextRandomBigInteger(256);
		}
		// System.out.println(GCD(g, b));
		// Ginv = G.modInverse(Config.FIELD_PRIME);
		return g;

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

		candidate = createProverWitnessWire("candidate"); // 후보자

		E_id = createInputWireArray(leafNumOfWords, "e_id"); // 투표 번호

		SK_id = createProverWitnessWireArray(leafNumOfWords, "sk_id"); // voter private key

		EK_id = createProverWitnessWireArray(2, "ek_id"); // S = G ^ s , T = (S ^ rho) * (G ^ real)

		Wire[] skBits = new WireArray(SK_id).getBits(leafWordBitWidth).asArray();

		SubsetSumHashGadget subsetSumGadget = new SubsetSumHashGadget(skBits, false);
		Wire[] leafWires = subsetSumGadget.getOutputWires();
		// PK_id = leafWires;
		directionSelector = createProverWitnessWire("Direction selector");
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");

		merkleTreeGadget = new MerkleTreePathGadget(directionSelector, leafWires, intermediateHasheWires, 254,
				treeHeight);
		Wire[] actualRoot = merkleTreeGadget.getOutputWires();

		Wire[] sn_input = Util.concat(E_id, SK_id);
		// for (int j = 0; j < 8; j++) {
		// sn_input[j] = SK_id[j];
		// }
		// for (int j = 8; j < 16; j++) {
		// sn_input[j] = pk_e[j-8];
		// }

		Wire[] snBits = new WireArray(sn_input).getBits(leafWordBitWidth).asArray();
		subsetSumGadget = new SubsetSumHashGadget(snBits, false);
		Wire[] out = subsetSumGadget.getOutputWires();

		makeOutputArray(out, "sn");

		for (int i = 0; i < actualRoot.length; i++) {
			actualRoot[i] = actualRoot[i];
		}

		makeOutputArray(actualRoot, "Computed Root");

		randomizedEnc = createProverWitnessWire("r");

		// Wire[] CT = new Wire[1 + num_of_elector];
		Wire[] VCT = new Wire[2];

		// CT[0] = power(pp[0], randomizedEnc);
		// CT[0] = pp[2].square(randomizedEnc); //CT[0] = G^r

		// CT[i + 1] = power(pp[i + 2], randomizedEnc).mul(power(pp[1], msg[i]));

		// for(int i = 0 ; i < num_of_elector ; i++)
		// {
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

			// for(i = 0; i < num_of_elector; i ++){ // 64
			// circuitEvaluator.setWireValue(candidate[i], 0);
			// }
			circuitEvaluator.setWireValue(candidate, 1);

			for (i = 0; i < leafNumOfWords; i++) { // 8 66 ~ 81 //람다 = 256
				circuitEvaluator.setWireValue(E_id[i], Integer.MAX_VALUE);
				circuitEvaluator.setWireValue(SK_id[i], Util.nextRandomBigInteger(32));
			}
			circuitEvaluator.setWireValue(directionSelector, 15); // 5742
			for (i = 0; i < hashDigestDimension * treeHeight; i++) { // 3 * 16 5743 ~ 5790
				circuitEvaluator.setWireValue(intermediateHasheWires[i], i);
			}
			BigInteger[] ekBigIntegers = new BigInteger[2];
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			try {
				for (i = 0; i < 2; i++) {
					ekBigIntegers[i] = Util.nextRandomBigInteger(256);
					output.write(ekBigIntegers[i].toByteArray());
					circuitEvaluator.setWireValue(EK_id[i], ekBigIntegers[i]);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

			circuitEvaluator.setWireValue(randomizedEnc, Util.nextRandomBigInteger(256));

		} else if (mode == 1) {
			int i = 0;
			circuitEvaluator.setWireValue(pp[0], pubp[0]);
			circuitEvaluator.setWireValue(pp[1], pubp[1]);

			// for(i = 0; i < num_of_elector; i ++){ // 64
			// circuitEvaluator.setWireValue(candidate[i], m[i]);
			// }
			circuitEvaluator.setWireValue(candidate, m);

			for (i = 0; i < leafNumOfWords; i++) { // 8 66 ~ 81
				circuitEvaluator.setWireValue(E_id[i], e_id[i]);
				circuitEvaluator.setWireValue(SK_id[i], sk_id[i]);
			}
			circuitEvaluator.setWireValue(directionSelector, 15); // 5742
			for (i = 0; i < hashDigestDimension * treeHeight; i++) { // 3 * 16 5743 ~ 5790
				circuitEvaluator.setWireValue(intermediateHasheWires[i], i);
			}
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			try {
				for (i = 0; i < 2; i++) {
					output.write(ek_id[i].toByteArray());
					circuitEvaluator.setWireValue(EK_id[i], ek_id[i]);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

			circuitEvaluator.setWireValue(randomizedEnc, Util.nextRandomBigInteger(256));
		}

	}

	public BigInteger Setup() {
		pubp = new BigInteger[2];
		G = Generator();
		rho = Util.nextRandomBigInteger(256);
		grho = G.modPow(rho, Config.FIELD_PRIME);

		e_id = new BigInteger[leafNumOfWords];
		for (int i = 0; i < leafNumOfWords; i++) {
			e_id[i] = Util.nextRandomBigInteger(32);
		}
		// bb=?

		pubp[0] = G;
		pubp[1] = grho;
		try {
			File file = new File("./datafiles/" + circuitName + "_PP.dat");

			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file));

			if (file.isFile() && file.canWrite()) {

				bufferedWriter.write(pubp[0].toString());
				bufferedWriter.newLine();
				bufferedWriter.write(pubp[1].toString());
				bufferedWriter.newLine();
				bufferedWriter.write(rho.toString());
				bufferedWriter.close();
			}
		} catch (IOException e) {
			System.out.println(e);
		}

		return rho;
	}

	public void init_DB() {

		PK_list = new BigInteger[list_size];
		for (int i = 0; i < list_size; i++)
			PK_list[i] = BigInteger.ZERO;
		PK_DB = new BigInteger[leafNumOfWords];
		ek_id = new BigInteger[num_of_voter * 2];
		for (int i = 0; i < 2 * num_of_voter; i++)
			ek_id[i] = Util.nextRandomBigInteger(256);

		// m = new BigInteger[num_of_elector];
		// for(int i = 0 ; i < num_of_elector ; i++)
		// m[i] = BigInteger.ZERO;
	}

	public boolean Register(int i) {
		sk_id = new BigInteger[leafNumOfWords];
		boolean success = true;
		for (int j = 0; j < leafNumOfWords; j++)
			sk_id[j] = Util.nextRandomBigInteger(32);
		BigInteger pk_id = getSHA256(sk_id);
		// BigInteger real = Util.nextRandomBigInteger(1);
		BigInteger real = BigInteger.ONE;

		BigInteger s = Util.nextRandomBigInteger(256);
		BigInteger r = Util.nextRandomBigInteger(256);
		BigInteger S = G.modPow(s, Config.FIELD_PRIME);
		BigInteger T = (S.modPow(rho, Config.FIELD_PRIME)).multiply(G.modPow(real, Config.FIELD_PRIME))
				.mod(Config.FIELD_PRIME);
		BigInteger R1 = S.modPow(r, Config.FIELD_PRIME);
		BigInteger R2 = G.modPow(r, Config.FIELD_PRIME);
		ek_id[i] = S;
		ek_id[i + num_of_voter] = T;
		for (int j = 0; j < list_size - 3; j += 3) {
			if ((PK_list[j].equals(ek_id[i]) == true) && PK_list[j + 1].equals(ek_id[i + num_of_voter]) == true
					&& PK_list[j + 2].equals(pk_id) == true) {
				success = false;
				break;
			} else {
				PK_list[j] = ek_id[i];
				PK_list[j + 1] = ek_id[i + num_of_voter];
				PK_list[j + 2] = pk_id;
			}
		}
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

	public BigInteger Vote(int i) {
		// V = new BigInteger[num_of_elector];
		// W = new BigInteger[num_of_elector];
		vct = new BigInteger[2];
		BigInteger r = Util.nextRandomBigInteger(256);
		sn = new BigInteger[leafNumOfWords];

		for (int j = 0; j < leafNumOfWords; j++)
			sn[j] = getSHA256(concat(e_id[j], sk_id[j]));
		/// rt, path <- membershipcheck(ek_id, pk_id)
		m = Util.nextRandomBigInteger(6);
		// m[v.intValue()].add(BigInteger.ONE);
		// for(int j = 0 ; j < num_of_elector; j++)
		// {
		vct[0] = G.modPow(r, Config.FIELD_PRIME).multiply((ek_id[i].modPow(m, Config.FIELD_PRIME)))
				.mod(Config.FIELD_PRIME);
		vct[1] = G.modPow((rho.multiply(r)), Config.FIELD_PRIME)
				.multiply((ek_id[i + num_of_voter].modPow(m, Config.FIELD_PRIME))).mod(Config.FIELD_PRIME);
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
			pw.write(i + "\t" + m.toString() + "\n");
			pw.flush();
			pw.close();
		} catch (IOException e) {
			System.out.println(e);
		}
		return m;
	}

	public static void main(String[] args) throws Exception {
		
		boolean reg;
		mode = 0;
		SimpleCircuitGenerator_vote_0923 generator = new SimpleCircuitGenerator_vote_0923("voting_ajitai16",
				16);
		// SimpleCircuitGenerator_tally tally = new
		// SimpleCircuitGenerator_tally("tally_ajtai16", 16);

		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		System.out.println("Hello Run Libsnark Setup");
		generator.runLibsnarksetup(0);
		// tally.generateCircuit();
		// tally.evalCircuit();
		// tally.prepFiles();
		// System.out.println("Tally setup");
		// tally.runLibsnarksetup();
		generator.init_DB();
		BigInteger sk = generator.Setup();
		mode = 1;
		for (int i = 1; i <= num_of_voter; i++) {
			reg = generator.Register(i);
			// System.out.println(reg);
			if (reg == false)
				return;
			BigInteger msg = generator.Vote(i);

			System.out.println("voter no : " + i + "\t" + msg);

			// generator.generateCircuit();
			generator.evalCircuit();
			generator.prepFiles();

			System.out.println("Hello Run Libsnark");
			generator.runLibsnarkproof(i);
			generator.runLibsnarkVerify(i);
			// tally.setMode(mode); //tally phase

			// BigInteger message = tally.Tally(pubp, sk, vct, m);
			// System.out.println(message);
		}
		// tally.setMode(mode); //tally phase

		// tally.Tally(pp, rho, VCT, M)

	}

}
