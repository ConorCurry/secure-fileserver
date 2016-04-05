/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.*;
import java.util.*;
import java.io.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.Scanner;

public class FileThread extends Thread
{
	private final Socket socket;
	private static final String RSA_METHOD = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
	private static final String SYM_METHOD = "AES/CBC/PKCS5Padding";
	private ObjectInputStream input;
	private ObjectOutputStream output;
	private PublicKey groupkey;
	private SecretKey identity_key;
	private SecretKey symKey;
	private static int t = 0;
	private PrivateKey serverKey = null;
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
			System.out.println("*** New connection from " + socket.getInetAddress() + " : " + socket.getPort() + "***");
			input = new ObjectInputStream(socket.getInputStream());
			output = new ObjectOutputStream(socket.getOutputStream());
			symKey = null;
		    Envelope msg = (Envelope)input.readObject();
		    boolean authOrNot = false;
		    if(msg.getMessage().equals("GetPubKey"))
		    {
		    	Envelope rsp = null;
		    	//load group server's public key 
				try
				{
					//read in server's public key from the file storing server's public key 
		            FileInputStream kfisp = new FileInputStream("FileServerPublicKey.bin");
		            ObjectInputStream fileServerKeysStream = new ObjectInputStream(kfisp);
		            rsp = new Envelope("OK");
		            rsp.addObject(((ArrayList<PublicKey>)fileServerKeysStream.readObject()).get(0));
		            kfisp.close();
		            fileServerKeysStream.close();
		            authOrNot = true;
				}
				catch(Exception ex)
				{
					System.out.println("Fail to load public key" + ex);
					socket.close();
					System.out.println("Socket close");
					proceed = false;
					rsp = new Envelope("FAIL");
				}
				output.writeObject(rsp);
				}
		    if(proceed)
		    {
			    if(authOrNot)
			    {	
				   if ((symKey = authenticate()) == null) {
							socket.close();
							proceed = false;
							System.out.println("Auth failed, closing connection.");
					}
				}
				else
				{
					 if ((symKey = authenticate(msg)) == null) {
							socket.close();
							proceed = false;
							System.out.println("Auth failed, closing connection.");
					}
				}
			}

			Envelope response;
			
			//load group server's public key 
			try
			{
				//read in server's public key from the file storing server's public key 
		        FileInputStream kfis = new FileInputStream("ServerPublic.bin");
		        ObjectInputStream serverKeysStream = new ObjectInputStream(kfis);
		        groupkey = ((ArrayList<PublicKey>)serverKeysStream.readObject()).get(0);
		        kfis.close();
		        serverKeysStream.close();
			}
			catch(Exception ex)
			{
				System.out.println("Fail to load public key" + ex);
				try
				{
					socket.close();
					System.out.println("connection is closed.");
					proceed = false;
				}
				catch(Exception exx)
				{
					System.out.println("Fail to close the file server.");
				}
			}

		   	while (proceed)
			{
				Envelope e;
				Object read_object = input.readObject();
				if(read_object.getClass().getName().equals("Envelope"))
				{
					e = (Envelope)read_object;
				}
					else
				{
				 	e = (Envelope)(((SealedObject)read_object).getObject(symKey));
				}
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
							ArrayList<String> filenames = null;
							if(yourToken.tokVerify(groupkey) && tokVerifyIandT(yourToken)) {
								
									List<String> groupPermits = yourToken.getGroups();
							    
									filenames = FileServer.fileList.fileAccess(groupPermits);
					            
									response = new Envelope("OK");
   							} else {
								response = new Envelope("FAIL-BADTOKEN");
							}
							response.addObject(filenames);
				        }
			        }
			        output.writeObject(response.encrypted(symKey));
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
							int index = (Integer)e.getObjContents().get(3); //extract the index of the key used 
							if(yourToken.tokVerify(groupkey) && tokVerifyIandT(yourToken)) {

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

									e = (Envelope) ( (SealedObject)input.readObject() ).getObject(symKey);
									while (e.getMessage().compareTo("CHUNK")==0) {
										fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
										response = new Envelope("READY"); //Success
										output.writeObject(response.encrypted(symKey));
										e = (Envelope) ( (SealedObject)input.readObject() ).getObject(symKey);
									}

									if(e.getMessage().compareTo("EOF")==0) {
										System.out.printf("Transfer successful file %s\n", remotePath);
										FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, index);
										response = new Envelope("OK"); //Success
									}
									else {
										System.out.printf("Error reading file %s from client\n", remotePath);
										response = new Envelope("ERROR-TRANSFER"); //Success
									}
									fos.close();
								}
							} else {
						   		response = new Envelope("FAIL-BADTOKEN");
					   		}
						}
					}

					output.writeObject(response.encrypted(symKey));
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					if(t.tokVerify(groupkey) && tokVerifyIandT(t)) {
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
										int i = 0;
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
											if(i == 0) e.addObject(new Integer(sf.getKeyIndex()));

											output.writeObject(e.encrypted(symKey));

											e = (Envelope) ( (SealedObject)input.readObject() ).getObject(symKey);
											i++;

										} while (fis.available()>0);

										//If server indicates success, return the member list
										if(e.getMessage().compareTo("DOWNLOADF")==0)
											{

												e = new Envelope("EOF");
												output.writeObject(e.encrypted(symKey));

												e = (Envelope) ( (SealedObject)input.readObject() ).getObject(symKey);
												if(e.getMessage().compareTo("OK")==0) {
													System.out.printf("File data download successful\n");
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
					} else {
						response = new Envelope("FAIL-BADTOKEN");
						output.writeObject(response.encrypted(symKey));
					}
				}			   	
				else if (e.getMessage().compareTo("DELETEF")==0) {
					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if(t.tokVerify(groupkey) && tokVerifyIandT(t)) {
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_DOESNTEXIST");
						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
						}
						else {

							try	{
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
					} else {
						e = new Envelope("FAIL-BADTOKEN");
						output.writeObject(e.encrypted(symKey));
					}
				}
	      	else if(e.getMessage().equals("DISCONNECT"))
   	   		{
	   				socket.close();
   					proceed = false;
				}
			} // end while	
		} 
		
      	catch(Exception ex)
			{
				System.err.println("Error: " + ex.getMessage());
				ex.printStackTrace(System.err);
			}
	}

	//TODO: ADD TIMEOUT FOR AUTH PROCEDURE
	
	private SecretKey authenticate() {
		SecretKey AESKey = null;
		Cipher cipher = null;
		PrivateKey serverKey = null;
		PublicKey userKey = null;
		Envelope challenge = null;
		byte[] rand;
		byte[] concat;
		KeyGenerator keyGen = null;
		try {
			challenge = (Envelope)input.readObject();
			System.out.println("Authenticating new connection...");
		} catch (Exception e) {
			System.err.println("Unable to recieve object: " +  e);
			return null;
		}
		if (challenge == null || !challenge.getMessage().equals("AUTH") || challenge.getObjContents().size() != 2) {
			return null;
		}
		
		//Stage0 -- load private key
		try {	
			//generate the secret key to decrypt the private key 
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update((FileServer.password).getBytes());
			byte[] hashedPassword = messageDigest.digest();

			//read in encrypted private key 
			FileInputStream fis = new FileInputStream("FileServerPrivateKey.bin");
			ObjectInputStream keyStream = new ObjectInputStream(fis);   
			ArrayList<byte[]> server_priv_byte = (ArrayList<byte[]>)keyStream.readObject();
			keyStream.close();
			fis.close();

			byte[] key_data = server_priv_byte.get(0);
			byte[] salt = server_priv_byte.get(1);
			
			//decrypt the one read from the file to get the server's private key 
			Cipher cipher_privKey = Cipher.getInstance(SYM_METHOD, "BC");
			//create a shared key with the user's hashed password 
			SecretKeySpec skey = new SecretKeySpec(hashedPassword, "AES");

			IvParameterSpec ivSpec = new IvParameterSpec(salt);
			cipher_privKey.init(Cipher.DECRYPT_MODE, skey, ivSpec);
			byte[] decrypted_data = cipher_privKey.doFinal(key_data);
			
			//recover the private key from the decrypted byte array 
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			serverKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decrypted_data));

		} catch (Exception e) {
			System.err.println("Unable to load private key: " + e);
			return null;
		}
		//Stage1 -- handle receiving initial auth request
		// try {
		// 	cipher = Cipher.getInstance(RSA_METHOD, "BC");
		// 	cipher.init(Cipher.DECRYPT_MODE, serverKey);
		// 	//rand = cipher.doFinal( (byte[])challenge.getObjContents().get(0) );
		// 	//userKey = (PublicKey)challenge.getObjContents().get(1);
		// 	//concat = cipher.doFinal( (byte[])challenge.getObjContents().get(0) );
		// 	int randLen = 8;
		// 	rand = Arrays.copyOfRange(concat, 0, randLen);
		// 	KeyFactory kf = KeyFactory.getInstance(RSA_METHOD, "BC");
		// 	userKey = kf.generatePublic(new X509EncodedKeySpec(Arrays.copyOfRange(concat, randLen, concat.length)));
		// } catch (Exception ex) {
		// 	System.err.println("Err in handling auth request part 1: " + ex);
		// 	return null;
		//}
		try {
			cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, serverKey);
			byte[] chal = (byte[])challenge.getObjContents().get(0);
			byte[] plain1 = cipher.doFinal(Arrays.copyOfRange(chal, 0, chal.length/2));
			byte[] plain2 = cipher.doFinal(Arrays.copyOfRange(chal, chal.length/2, chal.length));
			byte[] plain = new byte[(3072/8) * 2];
			System.arraycopy(plain1, 0, plain, 0, plain1.length);
			System.arraycopy(plain2, 0, plain, plain1.length, plain2.length);
			rand = Arrays.copyOfRange(plain, 0, 8);
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			userKey = kf.generatePublic(new PKCS8EncodedKeySpec(Arrays.copyOfRange(plain, 8, plain.length)));
			//userKey = (PublicKey)challenge.getObjContents().get(1);
		} catch (Exception ex) {
			System.err.println("AuthNoParam: Err in handling auth request part 1: " + ex);
			return null;
		}
		//Stage2 -- Construct AuthResponse
		try {
			//generate AES256 key as session key
			keyGen = KeyGenerator.getInstance("AES", "BC");
			keyGen.init(256, new SecureRandom());
			AESKey = keyGen.generateKey();
			//generate HMAC identity key
			keyGen = KeyGenerator.getInstance("HmacSHA256", "BC");
			keyGen.init(256, new SecureRandom());
			identity_key = keyGen.generateKey();
		} catch (Exception ex) {
			System.err.println("AuthNoParam: Error in handling auth request (RSA): " + ex);
			return null;
		}

		//Stage2.5 -- Auth response
		Envelope response = new Envelope("AUTH");
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(rand);
			cipher.init(Cipher.ENCRYPT_MODE, userKey);
			ByteArrayOutputStream msg = new ByteArrayOutputStream();
			//Add hash of challenge to response
			msg.write(messageDigest.digest());
			//Add chosen session key to response
			msg.write(AESKey.getEncoded());
			//add HMAC identity key to response
			msg.write(identity_key.getEncoded());
			//add timestamp, 30 random bits (to allow for additions)
			t = (new SecureRandom()).nextInt(2147483647/2);
			msg.write((Integer)t);
			//encrypt and send envelope
			response.addObject(cipher.doFinal(msg.toByteArray()));
			output.writeObject(response);
		} catch (Exception ex) {
			System.err.println("Error in encrypting/hashing auth response (RSA/SHA-256): " + ex);
			return null;
		}
		System.out.println("Authentication complete, success!");
		return AESKey; //auth steps complete		
	}
	
	private SecretKey authenticate(Envelope challenge) {
		SecretKey AESKey = null;
		Cipher cipher = null;
		PublicKey userKey = null;
		byte[] rand;
		KeyGenerator keyGen = null;
		
		if (challenge == null || !challenge.getMessage().equals("AUTH")) {
			return null;
		}
		
		//Stage0 -- load private key
		try {	
			//generate the secret key to decrypt the private key 
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update((FileServer.password).getBytes());
			byte[] hashedPassword = messageDigest.digest();

			//read in encrypted private key 
			FileInputStream fis = new FileInputStream("FileServerPrivateKey.bin");
			ObjectInputStream keyStream = new ObjectInputStream(fis);   
			ArrayList<byte[]> server_priv_byte = (ArrayList<byte[]>)keyStream.readObject();
			keyStream.close();
			fis.close();

			byte[] key_data = server_priv_byte.get(0);
			byte[] salt = server_priv_byte.get(1);
			
			//decrypt the one read from the file to get the server's private key 
			Cipher cipher_privKey = Cipher.getInstance(SYM_METHOD, "BC");
			//create a shared key with the user's hashed password 
			SecretKeySpec skey = new SecretKeySpec(hashedPassword, "AES");

			IvParameterSpec ivSpec = new IvParameterSpec(salt);
			cipher_privKey.init(Cipher.DECRYPT_MODE, skey, ivSpec);
			byte[] decrypted_data = cipher_privKey.doFinal(key_data);
			
			//recover the private key from the decrypted byte array 
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			serverKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decrypted_data));

		} catch (Exception e) {
			System.err.println("Unable to load private key: " + e);
			return null;
		}
		byte[] randChal;
		//Stage1 -- handle receiving initial auth request
		try {
			cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, serverKey);
			byte[] chal = (byte[])challenge.getObjContents().get(0);
			byte[] plain1 = cipher.doFinal(Arrays.copyOfRange(chal, 0, chal.length/2));
			byte[] plain2 = cipher.doFinal(Arrays.copyOfRange(chal, chal.length/2, chal.length));
			byte[] plain = new byte[(3072/8) * 2];
			System.arraycopy(plain1, 0, plain, 0, plain1.length);
			System.arraycopy(plain2, 0, plain, plain1.length, plain2.length);
			randChal = Arrays.copyOfRange(plain, 0, 8);
			byte[] encKey = Arrays.copyOfRange(plain, 8, 430);
			System.out.println("Rand: " + new String(randChal));
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			System.out.println(encKey.length);
			userKey = kf.generatePublic(new X509EncodedKeySpec(encKey));
			//userKey = (PublicKey)challenge.getObjContents().get(1);
		} catch (Exception ex) {
			System.err.println("Err in handling auth request part 1: ");
			ex.printStackTrace();
			return null;
		}
		//Stage2 -- Construct AuthResponse
		try {
			//generate AES256 key as session key
			keyGen = KeyGenerator.getInstance("AES", "BC");
			keyGen.init(256, new SecureRandom());
			AESKey = keyGen.generateKey();
			//generate HMAC identity key
			keyGen = KeyGenerator.getInstance("HmacSHA256", "BC");
			keyGen.init(256, new SecureRandom());
			identity_key = keyGen.generateKey();
		} catch (Exception ex) {
			System.err.println("AuthNoParam: Error in handling auth request (RSA): " + ex);
			return null;
		}

		//Stage2.5 -- Auth response
		Envelope response = new Envelope("AUTH");
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(randChal);
			cipher.init(Cipher.ENCRYPT_MODE, userKey);
			ByteArrayOutputStream msg = new ByteArrayOutputStream();
			//Add hash of challenge to response
			msg.write(messageDigest.digest());
			//Add chosen session key to response
			System.out.println("AES enc len: " + AESKey.getEncoded().length);
			msg.write(AESKey.getEncoded());
			//add HMAC identity key to response
			System.out.println("identikey enc len: " + identity_key.getEncoded().length);
			msg.write(identity_key.getEncoded());
			//add timestamp, 30 random bits (to allow for additions)
			t = (new SecureRandom()).nextInt(2147483647/2);
			msg.write((Integer)t);
			//encrypt and send envelope
			response.addObject(cipher.doFinal(msg.toByteArray()));
			output.writeObject(response);
		} catch (Exception ex) {
			System.err.println("Error in encrypting/hashing auth response (RSA/SHA-256): " + ex);
			return null;
		}
		/*
		//Stage2 -- Auth response
		Envelope response = new Envelope("AUTH");
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(randChal);
			cipher.init(Cipher.ENCRYPT_MODE, userKey);
			ByteArrayOutputStream msg = new ByteArrayOutputStream();
			msg.write(messageDigest.digest());
			msg.write(AESKey.getEncoded());
			response.addObject(cipher.doFinal(msg.toByteArray()));
			output.writeObject(response);
			output.flush();
			output.reset();
		} catch (Exception ex) {
			System.err.println("Error in encrypting/hashing auth response (RSA/SHA-256): " + ex);
			return null;
		}
		*/
		System.out.println("Authentication complete, success!");
		return AESKey; //auth steps complete		
		
	}
	//encrypts, hmacs, TODO timestamps
	private void sendEncryptedWithHMAC(Envelope message) { 
		try {
			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);

			Envelope to_be_sent = new Envelope("REQ");
												
			Cipher object_cipher = Cipher.getInstance(SYM_METHOD, "BC");
			object_cipher.init(Cipher.ENCRYPT_MODE, symKey);
								
			SealedObject hmac_msg_sealed = new SealedObject(message, object_cipher);
			to_be_sent.addObject(hmac_msg_sealed);
													
			byte[] rawHamc = mac.doFinal(convertToBytes(hmac_msg_sealed));
			to_be_sent.addObject(rawHamc);

			output.reset();
			output.writeObject(to_be_sent);
			output.flush();
			output.reset();
		} catch(Exception ex) {
			System.err.println("Error in sending encrypted response (AES/HMAC): " + ex);
		}
	}

	private Envelope recieveEncryptedWithHMAC() {
		Envelope response  = null;
		Envelope plaintext = null;
		try {			
			response = (Envelope)input.readObject();
			byte[] msg_combined_encrypted = convertToBytes((SealedObject)response.getObjContents().get(0));
			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(identity_key);
			byte[] rawHamc_2 = mac.doFinal(msg_combined_encrypted);
			byte[] Hmac_passed = (byte[])response.getObjContents().get(1);
			if(Arrays.equals(rawHamc_2, Hmac_passed)) {
				plaintext = (Envelope)((SealedObject)response.getObjContents().get(0)).getObject(symKey);
				int t_received = (Integer)plaintext.getObjContents().get(0);
				if(t_received == t) {
					t++;
				} else {
					System.out.println("The message is replayed/reordered.");
					socket.close();
				}
			}
		} catch(Exception e) {
			System.err.println("Error recieving an encrypted response (AES/HMAC): " + e);
		}
		return plaintext;
	}
	private byte[] convertToBytes(Object object){
 		try { 
    	   	ByteArrayOutputStream bos = new ByteArrayOutputStream();
         	ObjectOutputStream out = new ObjectOutputStream(bos);
        	out.writeObject(object);
        	bos.close();
        	out.close();
        	return bos.toByteArray();
    	} catch (Exception byte_exception) {
				System.out.println("Can't convert object to a byte array");
				return null;
		}
	}

	public boolean tokVerifyIandT(UserToken token)
	{
		try
		{
			byte[] to_be_verified = token.getEncryptedTime();
			Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
			cipher.init(cipher.DECRYPT_MODE, serverKey);
		    byte[] decrypted_data = cipher.doFinal(to_be_verified);
		    ByteArrayInputStream baos = new ByteArrayInputStream(decrypted_data);
	        DataInputStream dos = new DataInputStream(baos);
	        long result=dos.readLong();
	        dos.close();
			if((new Date()).getTime() - result < 600000)
					return true;
		}
		catch(Exception e)
		{
			System.out.println("Fail to retrieve time stamp of the token.");
			System.out.println(e);
			return false;
		}
		return false;
	}
}
