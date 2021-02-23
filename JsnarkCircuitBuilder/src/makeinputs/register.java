/*******************************************************************************
 * Author: Seongho Park <shparkk95@kookmin.ac.kr>
 *******************************************************************************/
package examples.makeinputs;

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

public class register {
	private int leafNumOfWords = 8;
	private BigInteger[][] pp;
	private BigInteger[] e_id;
	private BigInteger[] sk_id;
	private BigInteger[][] ek_id;
	private BigInteger G;
	private BigInteger Grho;
	private BigInteger msg;
	private BigInteger rho;
	
	public register(int voterno)
	{
		this.ReadCRS();
		this.reg(voterno);
	}

    public boolean reg(int voterno){
        sk_id = new BigInteger[leafNumOfWords];
		ek_id = new BigInteger[2][leafNumOfWords];
		boolean success = true;
		for (int j = 0; j < leafNumOfWords; j++)
			sk_id[j] = Util.nextRandomBigInteger(32);
		// Register register = new Register("register", 1);
		// register.sk_id = sk_id;
		// register.generateCircuit();
		// register.evalCircuit();
		// register.pFiles();
		// register.runLibsnarkproof(voterno);
		// register.runLibsnarkVerify(voterno);
		// System.out.println("register verify");

		
		BigInteger real = BigInteger.ONE;
		BigInteger s = Util.nextRandomBigInteger(256);
		BigInteger r = Util.nextRandomBigInteger(256);
		BigInteger S = G.modPow(s, Config.FIELD_PRIME);
		BigInteger T = (S.modPow(rho, Config.FIELD_PRIME)).multiply(G.modPow(real, Config.FIELD_PRIME))
				.mod(Config.FIELD_PRIME);
		BigInteger R1 = S.modPow(r, Config.FIELD_PRIME);
		BigInteger R2 = G.modPow(r, Config.FIELD_PRIME);
		ek_id[0] = Util.split(G, 32);
		ek_id[1] = Util.split(T, 32);
		
		BigInteger C = Util.nextRandomBigInteger(256);
		BigInteger K = r.add(C.multiply(rho));
		BigInteger SpowK = S.modPow(K, Config.FIELD_PRIME);
		BigInteger TdivG = BigInteger.ONE;
		if (real.equals(BigInteger.ONE) == true)
			TdivG = T.multiply(G.modInverse(Config.FIELD_PRIME)).mod(Config.FIELD_PRIME);
		else
			TdivG = T;
		if (SpowK.equals((TdivG.modPow(C, Config.FIELD_PRIME)).multiply(R1).mod(Config.FIELD_PRIME)) == false) {
			System.out.print(voterno + "\t");
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
			System.out.print(voterno + "\t");
			// System.out.print(G.modPow(K[i], Config.FIELD_PRIME) + "\t");
			// System.out.print((GpowR.modPow(C[i],
			// Config.FIELD_PRIME)).multiply(R2[i]).mod(Config.FIELD_PRIME) + "\t");

			success = false;
		}

		return success;
    }

	public void ReadCRS() {
		System.out.println("reading CRS");
		pp = new BigInteger[2][leafNumOfWords];
		try {
            // 파일 객체 생성
            File file = new File("./datafiles/" + "PP.dat");
            // 입력 스트림 생성
            FileReader filereader = new FileReader(file);
            // 입력 버퍼 생성
            BufferedReader bufReader = new BufferedReader(filereader);
			String line = "";
			int j = 0 ;
			while ((line = bufReader.readLine()) != null) {
				if (j == 0) {
					G = new BigInteger(line);
					j = 1;
				}
				if (j == 1) {
					Grho = new BigInteger(line);
				}
			}

            // .readLine()은 끝에 개행문자를 읽지 않는다.  
            filereader.close();
            bufReader.close();
        } catch (FileNotFoundException e) {
            // TODO: handle exception
        } catch (IOException e) {
            System.out.println(e);
        }
		pp[0] = Util.split(G, 32);
		pp[1] = Util.split(Grho, 32);
		e_id = new BigInteger[leafNumOfWords];
		try {
            // 파일 객체 생성
            File file = new File("./datafiles/" + "e_id.dat");
            // 입력 스트림 생성
            FileReader filereader = new FileReader(file);
            // 입력 버퍼 생성
            BufferedReader bufReader = new BufferedReader(filereader);
			String line = "";
			int i = 0;
			while ((line = bufReader.readLine()) != null) {
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
		try {
            // 파일 객체 생성
            File file = new File("./datafiles/" + "sk.dat");
            // 입력 스트림 생성
            FileReader filereader = new FileReader(file);
            // 입력 버퍼 생성
            BufferedReader bufReader = new BufferedReader(filereader);
			String line = "";
			while ((line = bufReader.readLine()) != null) {
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
		
		System.out.println("reading CRS done");

	}

    public static void main(String[] args){
        register register = new register(0);
    }
    
}
