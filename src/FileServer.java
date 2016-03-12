/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import org.bouncycastle.jce.provider.*;
import java.security.*;
import javax.crypto.*;

public class FileServer extends Server {
	
	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	
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
		PublicKey pubKey;
		String privKeyFile = "FileServerPrivateKey.bin";
		PrivateKey privKey;
		ObjectInputStream fileStream;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);
		
		//Filelist management
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		} catch(FileNotFoundException e) {
			System.out.println("FileList Does Not Exist. Creating FileList...");
			
			fileList = new FileList();
			
		} catch(IOException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		} catch(ClassNotFoundException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}

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
		
		//keyPair management
		try {
			FileInputStream fis = new FileInputStream(pubKeyFile);
			fileStream = new ObjectInputStream(fis);
			pubKey = (PublicKey)fileStream.readObject();
			fileStream.close();
			fis.close();

			fis = new FileInputStream(privKeyFile);
			fileStream = new ObjectInputStream(fis);
			privKey = (PrivateKey)fileStream.readObject();
			System.out.println("Read key objects");
			fileStream.close();
			fis.close();
		} catch(FileNotFoundException e) {
			System.out.print("Keys cannot be found, generating a new keypair...");
			try {
				KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
				keyPairGen.initialize(3072, new SecureRandom());
				KeyPair pair = keyPairGen.generateKeyPair();
				
				FileOutputStream fos = new FileOutputStream(pubKeyFile);
				ObjectOutputStream keysOut = new ObjectOutputStream(fos);
				keysOut.writeObject(pair.getPublic());
				keysOut.close();
				fos.close();

				fos = new FileOutputStream(privKeyFile);
				keysOut = new ObjectOutputStream(fos);
				//TODO: encrypt private key with passphrase
				keysOut.writeObject(pair.getPrivate());
				keysOut.close();
				fos.close();
			} catch (Exception ex) {
				System.err.println("Error creating new keypair: " + ex);
				System.exit(-1);
			}
				
		} catch(IOException e) {
			System.out.println("Error reading from key files");
			System.exit(-1);
		} catch(ClassNotFoundException e) {
			System.out.println("Error reading from key files");
			System.exit(-1);
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
