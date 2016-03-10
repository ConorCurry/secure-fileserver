/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
import java.io.ObjectInputStream;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.*;

public class GroupClient extends Client implements GroupClientInterface {
 
	 //send the user name and challenge to the server 
	 public boolean authenticate(String username, PrivateKey usrPrivKey, PublicKey serverPubey, SecretKey AES_key)
	 {
	 	try
	 	{
	 		Security.addProvider(new BouncyCastleProvider());
	 		
	 		Envelope message = null;
	 		SealedObject response = null;
	 		message = new Envelope("CHALLENGE");
	 		message.addObject(username);
	 		
	 		//random generate a 64-bit number, encrypt it, and add that to the message 
	 		SecureRandom sr = new SecureRandom();
			byte[] rndBytes = new byte[8];
			sr.nextBytes(rndBytes);
	 		Cipher cipher = Cipher.getInstance("RSA", "BC");
	 		cipher.init(Cipher.ENCRYPT_MODE, serverPubkey);
	 		message.addObject(cipher.doFinal(rndBytes));
	 		
	 		//encrypt the secret key 
	 		byte[] key_data = AES_key.getEncoded();
	 		cipher.init(Cipher.ENCRYPT_MODE, serverPubkey);
			byte[] encrypted_data = cipher.doFinal(key_data);
			message.addObject(encrypted_data);
	 		
	 		//generate signature for the encrypted secret key 
			Signature sig = Signature.getInstance("RSA", "BC");
			sig.initSign(usrPrivKey, new SecureRandom());
			//update encrypted data to be signed and sign the data 
			sig.update(encrypted_data);
			byte[] sigBytes = sig.sign();
	 		message.addObject(sigBytes);

	 		//sent object
	 		output.writeObject(message.encrypted(serverPubkey));
			output.flush();
			output.reset();
		
			//Get the response from the server
			response = (SealedObject)input.readObject();
			Cipher scipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			scipher.init(Cipher.DECRYPT_MODE, usrPrivKey);
			Envelope plain_response = (Envelope)response.getObject(scipher);
			
			//Successful response
			if(plain_response.getMessage().equals("OK"))
			{ 
				ArrayList<Object> temp = response.getObjContents();
				
				if(temp != null && temp.size() == 2)
				{
					byte[] numberFromServer = (byte[])temp.get(0);
					if(Arrays.equals(numberFromServer, rndBytes))
					{
						
						Cipher rcipher = Cipher.getInstance("RSA", "BC");
						rcipher.init(Cipher.DECRYPT_MODE, usrPrivKey);
			    		byte[] serverGeneratedNumber = rcipher.doFinal((byte[])temp.get(1));
			    	 	message = new Envelope ("Verify");
			    	 	message.addObject(serverGeneratedNumber);
			    	 	output.writeObject(message.encrypted(AES_key));
						output.flush();
						output.reset();
						
						SealedObject second_response = (SealedObject)input.readObject();
						Cipher sdcipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
						sdcipher.init(Cipher.DECRYPT_MODE, AES_key);
						Envelope plain_response = (Envelope)response.getObject(sdcipher);
			
						//Successful response
						if(plain_response.getMessage().equals("OK")) return true;
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
			output.writeObject(message);
			output.flush();
			output.reset();
		
			//Get the response from the server
			response = (Envelope)input.readObject();
			
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
			output.writeObject(message);
			output.reset();
		
			//Get the response from the server
			response = (Envelope)input.readObject();
			
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
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				
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
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				
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
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
				
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
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
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
			 output.writeObject(message); 
			 
			 response = (Envelope)input.readObject();
			 
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
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
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
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
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
