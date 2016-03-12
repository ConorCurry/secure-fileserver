/* Implements the GroupClient Interface */

import java.util.*;
import java.io.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;

public class GroupClient extends Client implements GroupClientInterface {
 	 private static final String RSA_Method = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
	 private static final String AES_Method = "AES/CBC/PKCS5Padding";
	 private static SecretKey AES_key = null;
	 //send the user name and challenge to the server 
	 public boolean authenticate(String username, PrivateKey usrPrivKey, PublicKey serverPubkey, SecretKey AES)
	 {
	 	try
	 	{

	 		AES_key = AES;
	 		Security.addProvider(new BouncyCastleProvider());
	 		
	 		Envelope message = null;
	 		Envelope response = null;
	 		message = new Envelope("CHALLENGE"); //Actually don't care 
	 		message.addObject(username);
	 		
	 		//random generate a 64-bit number, encrypt it, and add that to the message 
	 		SecureRandom sr = new SecureRandom();
			byte[] rndBytes = new byte[8];
			sr.nextBytes(rndBytes);
	 		
	 		Cipher cipher = Cipher.getInstance(RSA_Method, "BC");
	 		cipher.init(Cipher.ENCRYPT_MODE, serverPubkey);
	 		message.addObject(cipher.doFinal(rndBytes));
	 		
	 		//encrypt the secret key 
	 		byte[] key_data = AES_key.getEncoded();
	 		cipher.init(Cipher.ENCRYPT_MODE, serverPubkey);
			byte[] encrypted_data = cipher.doFinal(key_data);
			message.addObject(encrypted_data);
	 		
	 		//generate signature for the encrypted secret key 
			Signature sig = Signature.getInstance("SHA256withRSA", "BC");
			sig.initSign(usrPrivKey, new SecureRandom());
			//update encrypted data to be signed and sign the data 
			sig.update(encrypted_data);
			byte[] sigBytes = sig.sign();
	 		message.addObject(sigBytes);

	 		//sent object
	 		output.writeObject(message);
			output.flush();
			output.reset();
		
			//Get the response from the server
			response = (Envelope)input.readObject();

			//if it's null and it's a failure message because the server can't find the user's public key to encrypt the message 
			//if its not null, it might be a succeess message 
			if(response != null)
			{
					//Successful response
					if(response.getMessage().equals("OK"))
					{ 
						ArrayList<Object> temp = response.getObjContents();
						
						if(temp != null && temp.size() == 2)
						{
							byte[] numberFromServer = (byte[])temp.get(0);
							if(Arrays.equals(numberFromServer, rndBytes))
							{
								
								//get the server's generated number
								Cipher rcipher = Cipher.getInstance(RSA_Method, "BC");
								rcipher.init(Cipher.DECRYPT_MODE, usrPrivKey);
					    		byte[] serverGeneratedNumber = rcipher.doFinal((byte[])temp.get(1));
					    	 	
					    	 	Envelope second_message = new Envelope ("VERIFY");
					    	 	second_message.addObject(serverGeneratedNumber);
					    	 	output.writeObject(second_message);
								output.flush();
								output.reset();
								
								Envelope second_response = (Envelope)((SealedObject)input.readObject()).getObject(AES_key);
								if((second_response.getMessage()).equals("OK"))
									return true;
							}
						}
					}
			}
			return false;
	 	}
	 	catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	 }

	 public UserToken getToken(String username)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			//output.reset();
			output.writeObject(message.encrypted(AES_key));
			output.flush();
			output.reset();
		
			//Get the response from the server
			response = (Envelope)((SealedObject)input.readObject()).getObject(AES_key);
			
			//System.out.printf("Server response msg: %s\n", response.getMessage());
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = response.getObjContents();
				
				if(temp != null && temp.size() == 1)
				{
					token = (UserToken)temp.get(0);
					return token;
				}
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
 	 
 	 public UserToken getToken(String username, ArrayList<String> groups)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("GET_SUBSET");
			message.addObject(username); //Add user name string
			message.addObject(groups);
			output.writeObject(message.encrypted(AES_key));
			output.reset();
		
			//Get the response from the server
			response = (Envelope)((SealedObject)input.readObject()).getObject(AES_key);
			
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 1)
				{
					token = (UserToken)temp.get(0);
					return token;
				}
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
	 public boolean createUser(String username, UserToken token, PublicKey to_be_added)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(token); //Add the requester's token
				message.addObject(to_be_added);
				output.writeObject(message.encrypted(AES_key));
			
				response = (Envelope)((SealedObject)input.readObject()).getObject(AES_key);
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
			 
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token
				output.writeObject(message.encrypted(AES_key));
			
				response = (Envelope)((SealedObject)input.readObject()).getObject(AES_key);
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token
				output.writeObject(message.encrypted(AES_key)); 
			
				response = (Envelope)((SealedObject)input.readObject()).getObject(AES_key);
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message.encrypted(AES_key)); 
			
				response = (Envelope)((SealedObject)input.readObject()).getObject(AES_key);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token
			 output.writeObject(message.encrypted(AES_key)); 
			 
			 response = (Envelope)((SealedObject)input.readObject()).getObject(AES_key);
			 
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 { 
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message.encrypted(AES_key)); 
			
				response = (Envelope)((SealedObject)input.readObject()).getObject(AES_key);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message.encrypted(AES_key));
			
				response = (Envelope)((SealedObject)input.readObject()).getObject(AES_key);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

}
