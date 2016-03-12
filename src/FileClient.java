/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.util.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class FileClient extends Client implements FileClientInterface {

	private static final String RSA_METHOD = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
	private static final String SYM_METHOD = "AES/CBC/PKCS5Padding";
	SecretKey symKey;

	//TODO: KEYPAIR AS A PARAMETER
	public boolean authenticate(/*KeyPair usrKeyPair,*/ UserToken token) {
		KeyPairGenerator keyPairGen = null;
		KeyPair usrKeyPair = null;
		PublicKey serverKey = null;
		Cipher cipher = null;
		SecureRandom srng = new SecureRandom();
		//64-bit random challenge
		byte[] rand = new byte[8];
		byte[] challenge = new byte[8];
		symKey = null;
		
		//TODO: REMOVE KEYPAIR GENERATION, INSTEAD TAKE FROM FILE
		try {
			keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGen.initialize(3072, new SecureRandom());
			usrKeyPair = keyPairGen.generateKeyPair();
		} catch (Exception ex) {
			System.err.println("Unable to create a keypair for the user: " + ex);
			return false;
		}
		
		//TODO: ENCRYPT PUBLIC KEY TO MAINTAIN CONFIDENTIALITY
		//TODO: USE DIFFERENT FILE FOR STORING SERVER PUBLIC KEY
		try {
			FileInputStream fis = new FileInputStream("FileServerPublicKey.bin");
			ObjectInputStream keyStream = new ObjectInputStream(fis);
			serverKey = (PublicKey)keyStream.readObject();
			keyStream.close();
			fis.close();
			if(serverKey == null) { 
				System.err.println("Unable to read server public key");
				return false; 
			} 
		} catch (Exception ex) {
				System.err.println("Unable to read server public key: " + ex);
				return false;
		}
		//byte[] enc_usr_public_key = null;
		srng.nextBytes(rand);

		//STAGE1 -- Initialize connecction, prepare challenge
		Envelope auth = new Envelope("AUTH");
		try {
			cipher = Cipher.getInstance(RSA_METHOD, "BC");
			cipher.init(Cipher.ENCRYPT_MODE, serverKey);
			challenge = cipher.doFinal(rand);
			//enc_usr_public_key = cipher.doFinal(usrKeyPair.getEncoded())
			
		} catch (Exception ex) {
			System.err.println("Encrypting Challenge Failed (RSA): " + ex);
			return false;
		}
		try {
			auth.addObject(challenge);
			auth.addObject(usrKeyPair.getPublic());	    		
			output.writeObject(auth);
		} catch (Exception ex) {
			System.err.println("Error sending authentication request: " + ex);
			return false;
		}
		//STAGE2 -- Validate server response & retrieve session key
		Envelope env = null;
		try {
			env = (Envelope)input.readObject();
		} catch (Exception ex) {
			System.err.println("Error recieving authentication response: " + ex);
			return false;
		}
		if(env != null && env.getMessage().equals("AUTH") && env.getObjContents().size() == 2) {
			try {
				//prepare validation cipher
				cipher.init(Cipher.DECRYPT_MODE, usrKeyPair.getPrivate());
				//validate challenge response
				byte[] challenge_response = cipher.doFinal( (byte[])env.getObjContents().get(0) );
				if (!Arrays.equals(challenge_response, rand)) {
					System.out.println("Server authenticity could not be verified");
					return false;
				}
				//retrieve AES256 session key
				symKey = (SecretKey)new SecretKeySpec(cipher.doFinal( (byte[])env.getObjContents().get(1) ), "AES");
			} catch (Exception e) {
				System.err.println("Error in validating challenge response / retreiving session key (RSA): " + e);
				return false;
			}			
		} else {
			System.err.println("Invalid server response");
			return false;
		}
		return true;
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
	    try {
			output.writeObject(env.encrypted(symKey));
		    env = (Envelope)( (SealedObject)input.readObject() ).getObject(symKey);
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
		
				File file = new File(destFile);
			    try {
			    				
				
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    
					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
					    output.writeObject(env.encrypted(symKey)); 
					
					    env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);
					    
						while (env.getMessage().compareTo("CHUNK")==0) { 
								fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								output.writeObject(env.encrypted(symKey));
								env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);		
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
							 System.out.printf("\nTransfer successful file %s\n", sourceFile);
							 env = new Envelope("OK"); //Success
							 output.writeObject(env.encrypted(symKey));
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
			    
					
				} catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				} catch (Exception ex) {
					ex.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token
			 output.writeObject(message.encrypted(symKey)); 
			 
			 try {
				 e = (Envelope)((SealedObject)input.readObject()).getObject(symKey);
			 } catch (Exception ex) {
				 System.err.println("Unable to read client message: " + e);
				 return null;
			 }
			 
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 { 
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		
		try
		 {
			 
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 output.writeObject(message.encrypted(symKey));
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 
			 env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 	
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					
					message.addObject(buf);
					message.addObject(new Integer(n));
					
					output.writeObject(message.encrypted(symKey));
					
					
					env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);
					
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");
				output.writeObject(message.encrypted(symKey));
				
				env = (Envelope)((SealedObject)input.readObject()).getObject(symKey);
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

}

