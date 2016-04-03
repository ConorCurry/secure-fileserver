/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.*;
import org.bouncycastle.jce.provider.*;
import java.security.*;
import javax.crypto.*;
import java.util.Scanner;
import java.util.ArrayList;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.Hashtable;

public class FileServer extends Server {
	
	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	public static String password;
	
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
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
			System.out.print("Please enter the system's password: ");
			password = console.nextLine();

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
				byte[] server_salt = new byte[16];
        		random.nextBytes(server_salt);
        		IvParameterSpec server_ivSpec = new IvParameterSpec(server_salt);
				//Actually encrypt the user's private key 
				Cipher scipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				//create a shared key with the user's hashed password 
				SecretKeySpec generated_skey = new SecretKeySpec(hashedPassword, "AES");
				scipher.init(Cipher.ENCRYPT_MODE, generated_skey, server_ivSpec);
				
				byte[] key_data = (kpn.getPrivate()).getEncoded();
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
			outStream.writeObject(FileServer.fileList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
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
					outStream.writeObject(FileServer.fileList);
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
}
