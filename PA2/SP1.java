import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

public class SP1 {
	private static byte[] nonce = new byte[32];

	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			PrivateKey privateKey = PrivateKeyReader();

			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					System.out.println("File received!");
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					int encryptNumBytes = fromClient.readInt();
					byte [] block = new byte[encryptNumBytes];
					fromClient.readFully(block, 0, encryptNumBytes);
					Cipher decipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					decipher.init(Cipher.DECRYPT_MODE, privateKey);
					byte[] decryptedBlock = decipher.doFinal(block);


					if (numBytes > 0)
						bufferedFileOutputStream.write(decryptedBlock, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();

					}
				} else if (packetType == 2) { //cp1
					InputStream fis = new FileInputStream("certificate_1004104.crt");
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					X509Certificate serverCertificate = (X509Certificate) cf.generateCertificate(fis);
					byte[] encodedServerCertificate = serverCertificate.getEncoded();

					fromClient.read(nonce);
					System.out.println("Getting client's nonce...");
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					cipher.init(Cipher.ENCRYPT_MODE, privateKey);
					System.out.println("Encrypting client's nonce...");
					byte[] encryptedNonce = cipher.doFinal(nonce);
					System.out.println("Encrypted!");
					toClient.write(encryptedNonce);
					System.out.println("Sent Encrypted Nonce to client!");
					toClient.flush();

					toClient.write(encodedServerCertificate);
					System.out.println("Sent Encoded Certificate to client!");
					toClient.flush();
				} else if (packetType == 4) { //close connection
					System.out.println("Closing connection...");
					fromClient.close();
					toClient.close();
					connectionSocket.close();
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}
	public static PrivateKey PrivateKeyReader() throws Exception{

		byte[] keyBytes = Files.readAllBytes(Paths.get("private_key.der"));

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

}
