import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CP2 {
	private static byte[] nonce = new byte[32];
	private static byte[] encryptedNonce = new byte[128];

	public static void main(String[] args) {

    	String filename;
    	String serverAddress = "localhost";
    	int port = 4321;

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {
			PublicKey publicKey = PublicKeyReader();
			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			InputStream fis = new FileInputStream("cacsertificate.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert = (X509Certificate)cf.generateCertificate(fis);
			PublicKey CAkey = CAcert.getPublicKey();

			toServer.writeInt(2);

			SecureRandom random = new SecureRandom(); //generate nonce
			random.nextBytes(nonce);
			toServer.write(nonce); //write nonce to the server

			fromServer.read(encryptedNonce); //get encrypted nonce from the server
			X509Certificate serverCertificate = (X509Certificate)cf.generateCertificate(fromServer); //get certificate from server

			serverCertificate.checkValidity();
			serverCertificate.verify(CAkey);

			PublicKey serverKey = serverCertificate.getPublicKey();
			Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decrypt.init(Cipher.DECRYPT_MODE, serverKey);
			byte[] decryptedNonce = decrypt.doFinal(encryptedNonce);

			if (Arrays.equals(nonce, decryptedNonce)) {
				System.out.println("Authenticated.");
			} else {
				toServer.writeInt(4);
				System.out.println("Authentication Failed.");
				toServer.close();
				fromServer.close();
				clientSocket.close(); //close all connections
			}

			SecretKey sessionKey = KeyGenerator.getInstance("AES").generateKey();
			Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
			byte[] encodedSessionKey = sessionKey.getEncoded();

			Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encryptedSessionKey = rsaCipher.doFinal(encodedSessionKey);

			System.out.println("Sending session key to server...");
			toServer.writeInt(3);
			toServer.writeInt(encryptedSessionKey.length);
			toServer.write(encryptedSessionKey);
			toServer.flush();
			System.out.println("Sent.");

			//to send multiple files
			for (int i = 0; i < args.length; i++) {
				filename = args[i];
				System.out.println("Sending" + filename);

				//send file name to server
				toServer.writeInt(0); 
				toServer.writeInt(filename.getBytes().length);
				toServer.write(filename.getBytes());
				toServer.flush();

				//open the file from the system
				fileInputStream = new FileInputStream(filename);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);

				byte[] fromFileBuffer = new byte[117];
				
				//send the file to the server
				for (boolean fileEnded = false; !fileEnded;) {
					numBytes = bufferedFileInputStream.read(fromFileBuffer);
					fileEnded = numBytes < 117;
	
					toServer.writeInt(1);
					toServer.writeInt(numBytes);

					//encrypting the file data
					byte[] encryptedFile = sessionCipher.doFinal(fromFileBuffer);
					toServer.writeInt(encryptedFile.length); 
					toServer.write(encryptedFile); //write to server
					toServer.flush();
				}
				System.out.println(filename + " sent successfully.");
				if (i == args.length - 1) {
					System.out.println("Closing connection...");
					toServer.writeInt(4);
					bufferedFileInputStream.close();
					fileInputStream.close();
				}
			}

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}

	public static PublicKey PublicKeyReader() throws Exception{

		byte[] keyBytes = Files.readAllBytes(Paths.get("public_key.der"));

		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);

	}
}
