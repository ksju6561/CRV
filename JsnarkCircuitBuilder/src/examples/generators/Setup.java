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


public class Setup {

	public static BigInteger G, Grho;
	public static BigInteger[] e_id;
	private int leafNumOfWords = 8;

	private BigInteger rho;
	private int treeHeight;

    public Setup() {
		

    }
    private static BigInteger GCD(BigInteger a,BigInteger b) { if (b.signum() == 0) { return a; } return GCD(b,a.mod(b)); }

	public BigInteger Generator()
	{
		BigInteger g, b = Config.FIELD_PRIME;
		g = Util.nextRandomBigInteger(256);
		while(GCD(g, b).compareTo(BigInteger.ONE) == 1)
			g = Util.nextRandomBigInteger(256);	
		 
		
		return g;

	}
	
	public BigInteger grho(BigInteger g)
	{
		rho = Util.nextRandomBigInteger(256);
		BigInteger grho = g.modPow(rho, Config.FIELD_PRIME);
		
        return grho;
	}

	public void OpenElection()
	{
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
				// bufferedWriter.newLine();
				// bufferedWriter.write(rho.toString());
				bufferedWriter.close();
			}
		} catch (IOException e) {
			System.out.println(e);
		}

	}

	public static void main(String[] args) throws Exception{
		Setup setup = new Setup();
		SimpleCircuitGenerator_vote_ajitai_HO vote = new SimpleCircuitGenerator_vote_ajitai_HO("vote", 16);
		SimpleCircuitGenerator_tally tally = new SimpleCircuitGenerator_tally("tally", 16);
		SimpleCircuitGenerator_register register = new SimpleCircuitGenerator_register("register");
		vote.generateCircuit();
		vote.evalCircuit();
		vote.prepFiles();
		vote.runLibsnarksetup(0);
		System.out.println("VOTE CRS");
		tally.generateCircuit();
		tally.evalCircuit();
		tally.prepFiles();
		tally.runLibsnarksetup(0);
		System.out.println("TALLY CRS");
		register.generateCircuit();
		register.evalCircuit();
		register.prepFiles();
		register.runLibsnarksetup(0);
		System.out.println("REGISTER CRS");

		setup.OpenElection();
		// System.out.println(setup.rho);
	}
}