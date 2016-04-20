/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.*;
import java.net.*;
import org.bouncycastle.jce.provider.*;
import java.security.*;
import javax.crypto.*;
import java.util.Scanner;
import java.util.ArrayList;
import javax.crypto.spec.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.Hashtable;

public class FileServer extends Server {
	
	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	public static String password;
	public static PrivateKey serverKey;
	public static Key skey;
	
	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}
	
	public void start() {
		Security.addProvider(new BouncyCastleProvider());
		String fileFile = "FileList.bin";
		String pubKeyFile = "FileServerPublicKey.bin";
		String privKeyFile = "FileServerPrivateKey.bin";
		ObjectInputStream fileStream;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);
		Scanner console = new Scanner(System.in);

		//Filelist management
		try
		{
			FileInputStream fisL = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fisL);
			byte[] fileListBytes = (byte[])fileStream.readObject();
			System.out.print("Please enter the system's password: ");
			password = console.nextLine();
			try
			{
				//read in encrypted private key 
				FileInputStream fis = new FileInputStream("FileServerPrivateKey.bin");
				ObjectInputStream keyStream = new ObjectInputStream(fis);   
				ArrayList<byte[]> server_priv_byte = (ArrayList<byte[]>)keyStream.readObject();
				keyStream.close();
				fis.close();

				byte[] key_data = server_priv_byte.get(0);
				byte[] salt = server_priv_byte.get(1);
				
				SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
				KeySpec ks = new PBEKeySpec(password.toCharArray(), salt, 1024, 256);
				SecretKey s = f.generateSecret(ks);
				skey = new SecretKeySpec(s.getEncoded(), "AES");
				
				//decrypt the one read from the file to get the server's private key 
				Cipher cipher_privKey = Cipher.getInstance("AES", "BC");
				cipher_privKey.init(Cipher.DECRYPT_MODE, skey);
				byte[] decrypted_data = cipher_privKey.doFinal(key_data);
				
				//recover the private key from the decrypted byte array 
				KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
				serverKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decrypted_data));

				cipher_privKey.init(Cipher.DECRYPT_MODE, skey);
				fileList = (FileList)convertObject(cipher_privKey.doFinal(fileListBytes));
			}
			catch(Exception e)
			{
				System.out.println("Can't read encrypted files");
			}

		} catch(FileNotFoundException e) {
			System.out.println("FileList Does Not Exist. Creating FileList...");
			
			fileList = new FileList();
			System.out.print("Please create a system's password: ");
			password = console.nextLine();
			
			//first start the system, start to generate a RSA key pairs for the file server 
			System.out.print("Generate a new keypair for File Server...");
			try {
				//generate a key pair for the server
	            KeyPairGenerator kpgn = KeyPairGenerator.getInstance("RSA", "BC");
	            kpgn.initialize(3072, new SecureRandom());
	            KeyPair kpn = kpgn.genKeyPair();

	            //create list to store public key
	            ArrayList<PublicKey> server_pub = new ArrayList<PublicKey>();
	            server_pub.add(kpn.getPublic());
	            //write server's public key to a file 
	            ObjectOutputStream sPubKOutStream = new ObjectOutputStream(new FileOutputStream(pubKeyFile));
	            sPubKOutStream.writeObject(server_pub);
	            sPubKOutStream.close();
				
				//hash the password and make it to be the secret key to encrypt the private keys 
				MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
				messageDigest.update(password.getBytes());
				byte[] hashedPassword = messageDigest.digest();
				
				//generate salt for the server 
				SecureRandom random = new SecureRandom();
				//generate salt for the server 
				byte[] server_salt = new byte[16];
        		random.nextBytes(server_salt);

				Cipher scipher = Cipher.getInstance("AES", "BC");
				SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
				KeySpec ks = new PBEKeySpec(password.toCharArray(), server_salt, 1024, 256);
				SecretKey s = f.generateSecret(ks);
				Key generated_skey = new SecretKeySpec(s.getEncoded(), "AES");
				skey = generated_skey;

				scipher.init(Cipher.ENCRYPT_MODE, generated_skey);
				serverKey = kpn.getPrivate();
				byte[] key_data = serverKey.getEncoded();
				byte[] encrypted_data = scipher.doFinal(key_data);

				ArrayList<byte[]> server_priv_salt = new ArrayList<byte[]>();
				server_priv_salt.add(encrypted_data);
				server_priv_salt.add(server_salt);
				//write server's encrypted private key to a file 
	            ObjectOutputStream sPrivKOutStream = new ObjectOutputStream(new FileOutputStream(privKeyFile));
	            sPrivKOutStream.writeObject(server_priv_salt);
	            sPrivKOutStream.close();
			} catch (Exception ex) {
				System.err.println("Error creating new keypair: " + ex);
				System.exit(-1);
			}
		} catch(IOException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		} catch(ClassNotFoundException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		console.close();

  		//shared_files management
		File file = new File("shared_files");
		if (file.mkdir()) {
			System.out.println("Created new shared_files directory");
		}
		else if (file.exists()){
			System.out.println("Found shared_files directory");
		}
		else {
			System.out.println("Error creating shared_files directory");				 
	    }
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();
		
		
		boolean running = true;
		
		try
		{			
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			
			Socket sock = null;
			Thread thread = null;
			
			while(running)
			{
				sock = serverSock.accept();
				thread = new FileThread(sock);
				thread.start();
			}
			
			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	private byte[] convertToBytes(Object object)
	{
 		try{ 
    	   	ByteArrayOutputStream bos = new ByteArrayOutputStream();
         	ObjectOutput out = new ObjectOutputStream(bos);
        	out.writeObject(object);
        	bos.close();
        	out.close();
        	return bos.toByteArray();
    	} 
    	catch (Exception byte_exception)
    	{
    		System.out.println("Can't convert object to a byte array");
    		return null;
    	}
	}

	private Object convertObject(byte[] data)
	{
   	 	try
   	 	{
	   	 	ByteArrayInputStream in = new ByteArrayInputStream(data);
	    	ObjectInputStream is = new ObjectInputStream(in);
	    	Object converted = is.readObject();
	    	is.close();
	    	in.close();
	    	return converted;
	    }
	    catch(Exception e)
	    {
	    	System.out.println("Can't convert byte to object!");
	    	return null;
	    }
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			Cipher cipher = Cipher.getInstance("AES", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, FileServer.skey);
			outStream.writeObject(cipher.doFinal(convertToBytes(FileServer.fileList)));
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	private byte[] convertToBytes(Object object){
 		try{ 
    	   	ByteArrayOutputStream bos = new ByteArrayOutputStream();
         	ObjectOutput out = new ObjectOutputStream(bos);
        	out.writeObject(object);
        	bos.close();
        	out.close();
        	return bos.toByteArray();
    	} 
    	catch (Exception byte_exception)
    	{
    		System.out.println("Can't convert object to a byte array");
    		return null;
    	}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					Cipher cipher = Cipher.getInstance("AES", "BC");
					cipher.init(Cipher.ENCRYPT_MODE, FileServer.skey);
					outStream.writeObject(cipher.doFinal(convertToBytes(FileServer.fileList)));
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
	private byte[] convertToBytes(Object object){
 		try{ 
    	   	ByteArrayOutputStream bos = new ByteArrayOutputStream();
         	ObjectOutput out = new ObjectOutputStream(bos);
        	out.writeObject(object);
        	bos.close();
        	out.close();
        	return bos.toByteArray();
    	} 
    	catch (Exception byte_exception)
    	{
    		System.out.println("Can't convert object to a byte array");
    		return null;
    	}
	}
}
