/* Group server. Server loads the users from UserList.bin, groups from GroupList.bin
 * If user/group list does not exist, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user/group lists to respective files.
 */


import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;
	public String password;
	public Key encrypt_key;
	public PrivateKey privKey;
	public PublicKey pubKey;

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		String userRequestsFile = "UserRequests.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));
		Security.addProvider(new BouncyCastleProvider());

		//Open user file to get user list
		try
		{
			FileInputStream ufis = new FileInputStream(userFile);
			FileInputStream gfis = new FileInputStream(groupFile);
			userStream = new ObjectInputStream(ufis);
			groupStream = new ObjectInputStream(gfis);
			byte[] u_bytes = (byte[])userStream.readObject();
			byte[] g_bytes = (byte[])groupStream.readObject();
			try
			{
				System.out.print("Please enter a password for the group server: ");
				password = console.next();

				//read in encrypted private key 
				ObjectInputStream sPrivKInStream = new ObjectInputStream(new FileInputStream("ServerPrivate.bin"));    
				ArrayList<byte[]> server_priv_byte = (ArrayList<byte[]>)sPrivKInStream.readObject();
				sPrivKInStream.close();

				byte[] key_data = server_priv_byte.get(0);
				byte[] salt = server_priv_byte.get(1);

				SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
				KeySpec ks = new PBEKeySpec((password).toCharArray(), salt, 1024, 256);
				SecretKey s = f.generateSecret(ks);
				encrypt_key = new SecretKeySpec(s.getEncoded(), "AES");
				
				//decrypt the one read from the file to get the server's private key 
				Cipher cipher_privKey = Cipher.getInstance("AES", "BC");
				cipher_privKey.init(Cipher.DECRYPT_MODE, encrypt_key);
				byte[] decrypted_data = cipher_privKey.doFinal(key_data);
				
				//recover the private key from the decrypted byte array 
				KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
				privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decrypted_data));
			        
			    //read in server's public key
			    ObjectInputStream sPubKInStream = new ObjectInputStream(new FileInputStream("ServerPublic.bin"));    
				pubKey = ((ArrayList<PublicKey>)sPubKInStream.readObject()).get(0);
				sPubKInStream.close();

				Cipher cipher_list = Cipher.getInstance("AES", "BC");
				cipher_list.init(Cipher.DECRYPT_MODE, encrypt_key);
				userList = (UserList)convertObject(cipher_list.doFinal(u_bytes));
				
				cipher_list = Cipher.getInstance("AES", "BC");
				cipher_list.init(Cipher.DECRYPT_MODE, encrypt_key);
				groupList = (GroupList)convertObject(cipher_list.doFinal(g_bytes));
			}
			catch(Exception ex)
			{
				System.out.println(ex.toString());
			}
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList/GroupList/Requests File Does Not Exist. Creating...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			System.out.print("Please create a password for your account: ");
			String user_password = console.next();
			System.out.print("Please create a password for the group server: ");
			password = console.next();

			try
			{			
				//generate empty hashtable for storing users requesting accounts
				Hashtable<String, PublicKey> requests_pubKeys = new Hashtable<String, PublicKey>();
				ObjectOutputStream reqsOut = new ObjectOutputStream(new FileOutputStream(userRequestsFile));
				reqsOut.writeObject(requests_pubKeys);
				reqsOut.close();
				System.out.println("UserRequests created.");
	
				//generate a key pair for the first user, store the user and public key in one file, and store the user and the encrypted private key in another file
				Hashtable <String, PublicKey> user_publicKeys = new Hashtable <String, PublicKey>();
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            	kpg.initialize(3072, new SecureRandom());
           	 	KeyPair kp = kpg.genKeyPair();
            	user_publicKeys.put(username, kp.getPublic());
	            
	            //write the updated table back to the file 
	            ObjectOutputStream uPubKOutStream = new ObjectOutputStream(new FileOutputStream("UserPublicKeys.bin"));
	            uPubKOutStream.writeObject(user_publicKeys);
	            uPubKOutStream.close();
				
				//Actually encrypt the user's private key 
				Cipher ucipher = Cipher.getInstance("AES", "BC");

				//generate a 16-bit salt
				SecureRandom random = new SecureRandom();
				byte[] user_salt = new byte[16];
				random.nextBytes(user_salt);

	            SecretKeyFactory fu = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
	            KeySpec ksu = new PBEKeySpec(user_password.toCharArray(), user_salt, 1024, 256);
	            SecretKey su = fu.generateSecret(ksu);
	            Key generated_skey = new SecretKeySpec(su.getEncoded(), "AES");

				ucipher.init(Cipher.ENCRYPT_MODE, generated_skey);
	                
				byte[] key_data = (kp.getPrivate()).getEncoded();
				byte[] encrypted_data = ucipher.doFinal(key_data);
				
				//one for storing salt value 
	            Hashtable <String, ArrayList<byte[]>> user_privKeys = new Hashtable <String, ArrayList<byte[]>>();
	            ArrayList<byte[]> salt_priv = new ArrayList<byte[]>();
	            salt_priv.add(encrypted_data);
	            salt_priv.add(user_salt);
	            user_privKeys.put(username, salt_priv);

	            //write the updated table back to the file 
	            ObjectOutputStream uPrivKOutStream = new ObjectOutputStream(new FileOutputStream("UserPrivateKeys.bin"));
	            uPrivKOutStream.writeObject(user_privKeys);
	            uPrivKOutStream.close();

	            //generate a key pair for the server
	            KeyPairGenerator kpgn = KeyPairGenerator.getInstance("RSA", "BC");
	            kpgn.initialize(3072, new SecureRandom());
	            KeyPair kpn = kpgn.genKeyPair();

	            ArrayList<PublicKey> server_pub = new ArrayList<PublicKey>();
	            pubKey = kpn.getPublic();
	            server_pub.add(pubKey);
	            //write server's public key to a file 
	            ObjectOutputStream sPubKOutStream = new ObjectOutputStream(new FileOutputStream("ServerPublic.bin"));
	            sPubKOutStream.writeObject(server_pub);
	            sPubKOutStream.close();

			
				//generate salt for the server 
				byte[] server_salt = new byte[16];
        		random.nextBytes(server_salt);

				Cipher scipher = Cipher.getInstance("AES", "BC");
				SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
				KeySpec ks = new PBEKeySpec(password.toCharArray(), server_salt, 1024, 256);
				SecretKey s = f.generateSecret(ks);
				Key generated_skey2 = new SecretKeySpec(s.getEncoded(), "AES");
				encrypt_key = generated_skey2;

				scipher.init(Cipher.ENCRYPT_MODE, generated_skey2);
				privKey = kpn.getPrivate();
				byte[] key_data2 = privKey.getEncoded();
				byte[] encrypted_data2 = scipher.doFinal(key_data2);
				
				ArrayList<byte[]> server_priv_salt = new ArrayList<byte[]>();
				server_priv_salt.add(encrypted_data2);
				server_priv_salt.add(server_salt);
				//write server's encrypted private key to a file 
	            ObjectOutputStream sPrivKOutStream = new ObjectOutputStream(new FileOutputStream("ServerPrivate.bin"));
	            sPrivKOutStream.writeObject(server_priv_salt);
	            sPrivKOutStream.close();

				//generate a 128 key for new group 
				KeyGenerator ed_key = KeyGenerator.getInstance("AES", "BC");
				ed_key.init(256, new SecureRandom()); //128-bit AES key
				SecretKey file_key = ed_key.generateKey();
		
				//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
				userList = new UserList();
				groupList = new GroupList();
				userList.addUser(username, kp.getPublic());
				groupList.addGroup("ADMIN", username, file_key);
	            groupList.addMember(username, "ADMIN");
				userList.addGroup(username, "ADMIN");
				userList.addOwnership(username, "ADMIN");
			}
	        catch (Exception en)
	        {
	        	 System.err.println("Error: " + en.getMessage());
                 en.printStackTrace(System.err);
	        }
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList or GroupList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList or GroupList file");
			System.exit(-1);
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s is up and running \n", this.getClass().getName());
			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				System.out.println("Accepted");
				thread = new GroupThread(sock, this);
				System.out.println("Start new thread");
				thread.start();
			}
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

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream uOutStream;
		ObjectOutputStream gOutStream;
		
		try
		{
			uOutStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			gOutStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			Cipher cipher_list = Cipher.getInstance("AES", "BC");
			cipher_list.init(Cipher.ENCRYPT_MODE, my_gs.encrypt_key);
			uOutStream.writeObject(cipher_list.doFinal(convertToBytes(my_gs.userList)));
			cipher_list.init(Cipher.ENCRYPT_MODE, my_gs.encrypt_key);
			gOutStream.writeObject(cipher_list.doFinal(convertToBytes(my_gs.groupList)));
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

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream uOutStream;
				ObjectOutputStream gOutStream;
				
				try
				{
					uOutStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					gOutStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					Cipher cipher_list = Cipher.getInstance("AES", "BC");
					cipher_list.init(Cipher.ENCRYPT_MODE, my_gs.encrypt_key);
					uOutStream.writeObject(cipher_list.doFinal(convertToBytes(my_gs.userList)));
					cipher_list.init(Cipher.ENCRYPT_MODE, my_gs.encrypt_key);
					gOutStream.writeObject(cipher_list.doFinal(convertToBytes(my_gs.groupList)));
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
		} while(true);
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
