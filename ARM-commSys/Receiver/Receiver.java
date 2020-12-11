//Maylinh Nguyen
//program for receiver in secure communication system between sender and receiver

import java.io.*;
import java.nio.file.*;
import java.nio.charset.Charset;
import java.util.*;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.lang.Exception;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Receiver
{
	private static SecretKeySpec aesKey;
	private static byte[] tempKey;

/****************************************************************************************************************************/
/*                                                       MAIN METHOD                                                        */
/****************************************************************************************************************************/
	public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException,
	InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		System.out.println("===========================EXECUTING RECEIVER FILE===========================");
		System.out.println(">> reading from Transmitted_Data");

		//read bytesList with ciphertext, encrypted AES key, mac key, mac from Transmitted_Data
		String filePath = "/home/seed/CS4600/FinalProject/Transmitted_Data";
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(filePath));
		@SuppressWarnings("unchecked")
		List<byte[]> bytesList = (List<byte[]>) in.readObject();
		in.close();

		//store ciphertext, encrypted AES key, mac key, sender mac from Transmitted_Data into byte[]
		byte[] ciphertext, aesKey, macKey, macS;
		ciphertext = bytesList.get(0);
		aesKey = bytesList.get(1);
		macKey = bytesList.get(2);
		macS = bytesList.get(3);

		//print ciphrtext, encrypted AES key, mac key, sender mac
		System.out.print("[ciphertext]: ");
		System.out.println(new String(ciphertext));
		System.out.print("[encrypted aes key]: ");
		System.out.println(new String(aesKey));
		System.out.print("[mac key]: ");
		System.out.println(new String(macKey));
		System.out.print("[mac]: ");
		System.out.println(new String(macS));

/**************************************************AUTHENTICATING SENDER MAC*************************************************/
		//create Mac object with HmacSHA256 algorithm specification
		Mac tempMac = Mac.getInstance("HmacSHA256");
		//initialize Mac with Mac key
		tempMac.init(new SecretKeySpec(macKey, "HmacSHA256"));
		//compute and store Mac
		byte[] macR = tempMac.doFinal(ciphertext);

		//compare sender Mac and receiver Mac
		System.out.println("\n[mac authentication]: " + new String(macR));
		System.out.println(">> sender and receiver mac match: " + Arrays.equals(macS, macR));
		//terminate program if mac authentication fails
		if (Arrays.equals(macS, macR) == false) {
			System.out.println(">> mac authentication failed\n>> terminating program");
			System.out.println("==============================EXECUTION COMPLETE=============================");
			System.exit(0); }

/********************************************DECRYPTING AES KEY USING PRIVATE KEY********************************************/
		//set path to receiver RSA private key .der file
		String path = "/home/seed/CS4600/FinalProject/Receiver/privKey.der";
		File file = new File(path);
		FileInputStream fis = new FileInputStream(file);
		DataInputStream dis = new DataInputStream(fis);

		//store reciver RSA private key in byte[]
		byte[] privateKey = new byte[(int) file.length()];
		dis.readFully(privateKey);
		dis.close();

		//convert receiver RSA private key to PKCS#8 format
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKeyR = (PrivateKey) keyFactory.generatePrivate(keySpec);

		//decrypt AES key and store in string using receiver RSA private key
		byte[] decryptedAESkey = decryptAESkey(privateKeyR, aesKey); 
		String AESkey = new String(decryptedAESkey);
		System.out.print("\n[decrypted aes key]: " + AESkey);

/**********************************************DECRYPTING MESSAGE USING AES KEY**********************************************/
		//decrypt sender message using AES key
		String ciphertxt = new String(ciphertext);
		String message = aesDecrypt(ciphertxt, AESkey);
		//print decrypted message
		System.out.print("[decrypted message]: " + message);

		System.out.println("==============================EXECUTION COMPLETE=============================");	
	}
/****************************************************************************************************************************/

/****************************************************************************************************************************/
/*                                                    ADDITIONAL METHODS                                                    */
/****************************************************************************************************************************/
	//decrypt AES key using receiver RSA private key and OAEP padding
	public static byte[] decryptAESkey(PrivateKey key, byte[] aes_key) throws NoSuchAlgorithmException, 
				NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(aes_key);
	}

	//set AES key using decrypted AES key
	public static void aesSetKey(String key)
	{
		MessageDigest sha = null;
		try {
			tempKey = key.getBytes("UTF-8");
			sha = MessageDigest.getInstance("SHA-1");
			tempKey = sha.digest(tempKey);
			tempKey = Arrays.copyOf(tempKey, 16);
			aesKey = new SecretKeySpec(tempKey, "AES");
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	//decrypt sender message using AES key 
	public static String aesDecrypt(String ciphertext, String key)
	{
		try {
			aesSetKey(key);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, aesKey);
			return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)));
		}
		catch (Exception e) {
			System.out.println("Error while decrypting: " + e.toString());
		}
		return null;
	}
}
/****************************************************************************************************************************/
