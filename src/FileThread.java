/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crpyto.*;
import java.security.*;

public class FileThread extends Thread
{
	private final Socket socket;
	private static final String RSA_METHOD = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
	private static final String SYM_METHOD = "AES/CBC/PKCS5Padding";

	public FileThread(Socket _socket)
	{
		Security.addProvider(new BouncyCastleProvider());
		socket = _socket;
	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			SecretKey symKey = null;
			
			//TODO: USER AUTHENTICATION PROTOCOL
			if (!authenticate(symKey)) {
				socket.close();
				proceed = false;
			}
			Envelope response;

		   	while (proceed)
			{
				Envelope e = (Envelope) ( (SealedObject)input.readObject() ).getObject(symKey);
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
				    if(e.getObjContents().size() < 1)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
						    UserToken yourToken = (UserToken)e.getObjContents().get(0);
						    List<String> groupPermits = yourToken.getGroups();
						    
				            ArrayList<String> filenames = FileServer.fileList.fileAccess(groupPermits);
				            
				            response = new Envelope("OK");
				            response.addObject(filenames);
				        }
			        }
			        output.writeObject(response.encrypted());
				}
				if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								output.writeObject(response.encrypted(symKey));

								Envelope e = (Envelope) ( (SealedObject)input.readObject() ).getObject(symKey);
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response.encrypted(symKey));
									Envelope e = (Envelope) ( (SealedObject)input.readObject() ).getObject(symKey);
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(response.encrypted(symKey));
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e.encrypted(symKey));

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e.encrypted(symKey));
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.writeObject(e.encrypted(symKey));

						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}


								e.addObject(buf);
								e.addObject(new Integer(n));

								output.writeObject(e.encrypted(symKey));

								Envelope e = (Envelope) ( (SealedObject)input.readObject() ).getObject(symKey);


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								output.writeObject(e.encrypted(symKey));

								Envelope e = (Envelope) ( (SealedObject)input.readObject() ).getObject(symKey);
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{


							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					output.writeObject(e.encrypted(symKey));

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} //end while
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	private boolean authenticate(SecretKey AESKey) {
		Cipher cipher;
		PrivateKey serverKey = READFILE;
		PublicKey userKey = null;
		Envelope challenge = (Envelope)input.readObject();
		byte[] rand;
		KeyGenerator keyGen = null;
		//SecretKey AESKey = null;

		if (challenge == null || !challenge.getMessage().equals("AUTH") || challenge.getObjContents().size() != 2) {
			return false;
		}
		
		//Stage1 -- handle receiving initial auth request
		try {
			cipher.getInstance(RSA_METHOD, "BC");
			cipher.init(Cipher.DECRYPT_MODE, serverKey);
			rand = cipher.doFinal( (byte[])challenge.getObjContents().get(0) );
			userKey = (PublicKey)challenge.getObjContents().get(1);
			//generate AES256 key
			keyGen = KeyGenerator.getInstance("AES", "BC");
			keyGen.init(256, new SecureRandom());
			AESKey = keyGen.generateKey();
		} catch (Exception e) {
			System.err.println("Error in handling auth request (RSA): " + e);
			return false;
		}

		//Stage2 -- Auth response
		Envelope response = new Envelope("AUTH");
		try {
			cipher.init(Cipher.ENCRYPT_MODE, userKey);
			response.addObject(cipher.doFinal(rand));
			response.addObject(cipher.doFinal(AESKey.getEncoded()));
			output.writeObject(response);
		} catch (Exception e) {
			System.err.println("Error in encrypting auth response (RSA): " + e);
			return false;
		}
		return true; //auth steps complete		
	}
}
