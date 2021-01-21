/*******************************************************************************
 * Author: Ahmed Kosba <akosba@cs.umd.edu>
 *******************************************************************************/
package examples.generators;

import java.io.ByteArrayOutputStream;

import java.math.BigInteger;
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
import circuit.auxiliary.LongElement;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.MerkleTreePathGadget;
import examples.gadgets.hash.SubsetSumHashGadget;

public class Setup {

	public BigInteger G;
	public BigInteger Grho;
	public BigInteger[] e_id;
	private int leafNumOfWords = 8;

	private BigInteger rho;
	private int treeHeight;

	public Setup() {

	}

	public BigInteger Generator() {
		BigInteger g = Util.nextRandomBigInteger(254);

		while (g.gcd(Config.FIELD_PRIME).compareTo(BigInteger.ONE) == 1)
			g = Util.nextRandomBigInteger(254);
		return g;
	}

	public BigInteger grho(BigInteger g) {
		rho = Util.nextRandomBigInteger(249);
		BigInteger grho = g.modPow(rho, Config.FIELD_PRIME);
		return grho;
	}

	public void OpenElection() {
		G = Generator();
		Grho = grho(G);
		e_id = new BigInteger[leafNumOfWords];
		for (int i = 0; i < leafNumOfWords; i++) {
			e_id[i] = Util.nextRandomBigInteger(32);
		}
		try {
			File file = new File("./datafiles/" + "PP.dat");

			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file));

			if (file.isFile() && file.canWrite()) {
				bufferedWriter.write(G.toString());
				bufferedWriter.newLine();
				bufferedWriter.write(Grho.toString());
				bufferedWriter.newLine();
			}

			bufferedWriter.close();
		} catch (IOException e) {
			System.out.println(e);
		}
		try {
			File file = new File("./datafiles/" + "sk.dat");

			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file));

			if (file.isFile() && file.canWrite()) {
				bufferedWriter.write(rho.toString());
				bufferedWriter.newLine();
			}
			bufferedWriter.close();

		} catch (IOException e) {
			System.out.println(e);
		}

		try {
			File file = new File("./datafiles/" + "e_id.dat");

			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file));

			if (file.isFile() && file.canWrite()) {
				for (int i = 0; i < leafNumOfWords; i++) {
					bufferedWriter.write(e_id[i].toString());
					bufferedWriter.newLine();
				}
				bufferedWriter.close();
			}
		} catch (IOException e) {
			System.out.println(e);
		}

	}

	public static void main(String[] args) throws Exception {
		Setup setup = new Setup();
		// Vote vote = new Vote("vote", 16);
		// Tally tally = new Tally("tally");
		// Register register = new Register("register");
		setup.OpenElection();
		// vote.setup();
		System.out.println("VOTE CRS");
		// tally.setup();
		// System.out.println("TALLY CRS");
		// register.setup();
		// System.out.println("REGISTER CRS");

		// System.out.println(setup.rho);

	}
}