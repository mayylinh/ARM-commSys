//Maylinh Nguyen
//program for sender in secure communication system between sender and receiver

import java.io.*;
import java.nio.file.*;
import java.nio.charset.Charset;
import java.util.*;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.lang.Exception;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
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

public class Sender
{
	private static PrivateKey rsaPrivKey;
	private static PublicKey rsaPubKey;
	private static List<byte[]> bytesList = new ArrayList<byte[]>();
	private static SecretKeySpec aesKey;
	private static byte[] tempKey;

/****************************************************************************************************************************/
/*                                                       MAIN METHOD                                                        */
/****************************************************************************************************************************/
	public static void main(String[] args) throws Exception
	{
		System.out.println("===========================EXECUTING SENDER FILE===========================");
/*******************************************GENERATING RSA PUBLIC-PRIVATE KEY PAIR*******************************************/
		//generate RSA key pair for sender
		rsaKeyPairGen();

		//print RSA public and private keys
        	System.out.println("[rsa public key]: " + Base64.getEncoder().encodeToString(getRSApubKey().getEncoded()));
        	System.out.println("[rsa private key]: " + Base64.getEncoder().encodeToString(getRSAprivKey().getEncoded()));
		//write Base64 encoded sender RSA keys to corresponding files
		System.out.print(">> rsa public key ");
        	transmitKeys("/home/seed/CS4600/FinalProject/pubKeyS", getRSApubKey().getEncoded());
		System.out.print(" pubKeyS (in shared folder)\n");
		System.out.print(">> rsa private key ");		
        	transmitKeys("/home/seed/CS4600/FinalProject/Sender/privKey", getRSAprivKey().getEncoded());
		System.out.print(" privKey\n\n");

/****************************************ENCRYPTING MESSAGE FROM .TXT FILE USING AES****************************************/
		final String aesKey;
		String plaintext, ciphertext, decrypted;

		//set paths to location of AES key and plaintext message
		aesKey = new String(Files.readAllBytes(Paths.get("/home/seed/CS4600/FinalProject/Sender/aesKey.txt")));
		plaintext = new String(Files.readAllBytes(Paths.get("/home/seed/CS4600/FinalProject/Sender/plaintext.txt")));

		//encrypt message and decrypt ciphertext using AES key to verify encryption
		ciphertext = aesEncrypt(plaintext, aesKey);
		decrypted = aesDecrypt(ciphertext, aesKey);

		//print plaintext, ciphertext, decryption
		System.out.print("[plaintext]: " + plaintext);
		System.out.println("[ciphertext]: " + ciphertext);
		System.out.print("[encryption verification]: " + decrypted);
		//convert encrypted message into byte[] and add to bytesList
		byte[] ciphertxt = ciphertext.getBytes();
		System.out.print(">> ciphertext ");
		transmitBytes(ciphertxt);
		System.out.println("\n");

/*************************************ENCRYPTING AES KEY USING RECEIVER'S RSA PUBLIC KEY*************************************/
		//set path to receiver RSA public key
		Path path = Paths.get("/home/seed/CS4600/FinalProject/pubKeyR");
		//remove extra information from receiver RSA public key
		String publicKey = new String(Files.readAllBytes(path), Charset.defaultCharset());
		String rsaPublicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----", "")
					       .replaceAll(System.lineSeparator(), "")
					       .replace("-----END PUBLIC KEY-----", "");
		byte[] encoded = Base64.getDecoder().decode(rsaPublicKey);

		//store receiver RSA public key in X.509 format
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
		PublicKey publicKeyR = (PublicKey)keyFactory.generatePublic(keySpec);

		//store receiver RSA public key in byte[]
		byte[] aes_key = aesKey.getBytes("UTF8");
		//encrypt AES key using receiver RSA public key
		byte[] encryptedAESkey = encryptAESkey(publicKeyR, aes_key);

		//print AES key and encrypted AES key
		System.out.print("[aes key]: " + aesKey);
		System.out.print("[");
		System.out.print("encrypted aes key]: " + new String(encryptedAESkey, "UTF-8"));
		//add encrypted AES key to bytesList
		System.out.print("\n");
		System.out.print(">> encrypted aes key ");
		transmitBytes(encryptedAESkey);
		System.out.println("\n");

/*****************************************CREATING MAC (MESSAGE AUTHENTICATION CODE)*****************************************/
		KeyGenerator macKeyGen = KeyGenerator.getInstance("DES");
		SecureRandom secRandom = new SecureRandom();
		
		//initialize key generator with SecureRandom object
		macKeyGen.init(secRandom);
		//generate key with randomized KeyGenerator object
		Key macKey = macKeyGen.generateKey();
		//print Mac key and encode it to bytes before adding to bytesList
		System.out.print("[mac key]: " + macKey.getEncoded() + "\n");
		System.out.print(">> mac key ");
		transmitBytes(macKey.getEncoded());
		System.out.print("\n");

		//create Mac object with HmacSHA256 algorithm specification
		Mac tempMac = Mac.getInstance("HmacSHA256");
		//initialize Mac with Mac key
		tempMac.init(macKey);
		//compute and store Mac
		byte[] bytes = ciphertext.getBytes();
		byte[] mac = tempMac.doFinal(bytes);

		//print Mac and add to bytesList
		System.out.print("[");
		System.out.print("mac]: " + new String(mac));
		System.out.print("\n>> mac ");
		transmitBytes(mac);

		//write bytesList with ciphertext, encrypted AES key, mac key, mac to Transmitted_Data
		String filePath = "/home/seed/CS4600/FinalProject/Transmitted_Data";
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(filePath));
		out.writeObject(bytesList);
		out.flush();
		System.out.print("\n\n>> list successfully written to Transmitted_Data"); 

		System.out.println("\n=============================EXECUTION COMPLETE============================");
	}
/****************************************************************************************************************************/

/****************************************************************************************************************************/
/*                                                    ADDITIONAL METHODS                                                    */
/****************************************************************************************************************************/
	//generate RSA key pair for sender
	public static void rsaKeyPairGen() throws NoSuchAlgorithmException 
	{
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024);
		KeyPair kp = keyPairGen.generateKeyPair();
		rsaPubKey = kp.getPublic();
		rsaPrivKey = kp.getPrivate();
	}

	//get and return sender RSA public key in base64 string format
    	public static PublicKey getRSApubKey() {
        	return rsaPubKey;
    	}

	//get and return sender RSA private key in base64 string format
	public static PrivateKey getRSAprivKey() {
        	return rsaPrivKey;
    	}

	//set AES key using string from aesKey.txt
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
	
	//encrypt message string from plaintext.txt using AES key
	public static String aesEncrypt(String plaintext, String key)
	{
		try {
			aesSetKey(key);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, aesKey);
			return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes("UTF-8")));
		}
		catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}

	//decrypt ciphertext generated from aesEncrypt using AES key to verify encryption
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

	//encrypt AES key using receiver RSA public key and OAEP padding
	public static byte[] encryptAESkey(PublicKey key, byte[] aes_key) throws BadPaddingException, 
			IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException
	{
    		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");   
    		cipher.init(Cipher.ENCRYPT_MODE, key);  
    		return cipher.doFinal(aes_key);
	}

	//write receiver RSA keys to corresponding files
	public static void transmitKeys(String outFile, byte[] bytes)
	{
		try {
			FileOutputStream out = new FileOutputStream(outFile);
			out.write(bytes);
			out.close();
			System.out.print("successfully written to");
		}
		catch (IOException e) {
			System.out.print("was not written to" + e.toString());
		}
	}

	//write encrypted message to Transmitted_Data
	public static void transmitData(String data)
	{
		String outFile = "/home/seed/CS4600/FinalProject/Transmitted_Data";
		try {
			BufferedWriter out = new BufferedWriter(new FileWriter(outFile, true));
			out.write(data + "\n");
			out.close();
			System.out.println("successfully written to Transmitted_Data\n");
		}
		catch (IOException e) {
			System.out.println("was not written to Transmitted_Data: " + e.toString());
		}
	}

	//add byte arrays to array list to be written into Transmitted_Data
	public static void transmitBytes(byte[] bytes)
	{
		try {
			bytesList.add(bytes);
			System.out.print("sucessfully added to list");
		}
		catch (Exception e) {
			System.out.print("was not added to list" + e.toString());
		}
	}
}
/****************************************************************************************************************************/
