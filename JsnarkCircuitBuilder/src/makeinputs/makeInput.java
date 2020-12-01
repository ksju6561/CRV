import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Scanner;

public class makeInput{
    public makeInput(int msgSize, String path1, String path2){
        try{
            Scanner scanner = new Scanner(new File("./voting.in"));
            File filetmp = new File("./voting_tmp.in");
			File filePublic = new File(path1);
            File filePrivate = new File(path2);
            
            FileWriter fwTmp = new FileWriter(filetmp,true);
			FileReader frPublic = new FileReader(filePublic);
            FileReader frPrivate = new FileReader(filePrivate);
            
			BufferedReader brPublic = new BufferedReader(frPublic);
            BufferedReader brPrivate = new BufferedReader(frPrivate);
            
            fwTmp.write(scanner.next() +" "+ scanner.next() + "\n");
            for(int i = 0; i < msgSize;i++){
                fwTmp.write(scanner.next() +" "+ scanner.next() + "\n");
            }
            
            BigInteger[] pkE = this.split(new BigInteger(brPublic.readLine()),8,32);
            for(int i = 0; i < pkE.length;i++){
                fwTmp.write(scanner.next() +" "+ pkE[i].toString(16) + "\n"); scanner.next();
            }
            BigInteger[] skid = this.split(new BigInteger(brPrivate.readLine()),8,32);
            for(int i = 0; i < skid.length;i++){
                fwTmp.write(scanner.next() +" "+ skid[i].toString(16) + "\n"); scanner.next();
            }
            BigInteger dirselector = new BigInteger(brPrivate.readLine());
            String s = scanner.next() +" "+  dirselector.toString(16) + "\n";
            fwTmp.write(s);s = scanner.next();
            while(scanner.hasNext()){
                BigInteger path = new BigInteger(brPrivate.readLine());
                s = scanner.next() +" "+  path.toString(16) + "\n";
                fwTmp.write(s); s = scanner.next();
            }

			fwTmp.close();
			brPublic.close();
            brPrivate.close();
            
            Runtime runtime = Runtime.getRuntime();
            Process process = runtime.exec("mv ./voting_tmp.in ./voting.in");
		}catch(FileNotFoundException e){
			System.err.println(e);
		}catch(IOException e){
			System.err.println(e);
		}
    }
    public BigInteger[] split(BigInteger input, int bitwidth, int blocksize){
        BigInteger cpy_input = input;
        BigInteger bitwidthBigInteger = new BigInteger("2").pow(bitwidth).subtract(BigInteger.ONE);
        BigInteger[] rst = new BigInteger[blocksize];
        //System.out.println(input.length * bitwidth);
        for(int i = 0; i < blocksize; i++){
            rst[i] = cpy_input.and(bitwidthBigInteger);
            cpy_input = cpy_input.shiftRight(bitwidth);
        }
        return rst;
    } 

    public static void main(String[] args) {
        System.out.println(args.length);
        makeInput mInput = new makeInput(Integer.parseInt(args[2]),args[0],args[1]);
    }
}