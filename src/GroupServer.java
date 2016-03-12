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
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.spec.IvParameterSpec;

public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;

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
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try
		{
			FileInputStream ufis = new FileInputStream(userFile);
			FileInputStream gfis = new FileInputStream(groupFile);
			userStream = new ObjectInputStream(ufis);
			groupStream = new ObjectInputStream(gfis);
			
			userList = (UserList)userStream.readObject();
			groupList = (GroupList)groupStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList or GroupList File Does Not Exist. Creating...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			System.out.print("Please create a password for your account: ");
			String user_password = console.next();
			System.out.print("Please create a password for the group server: ");
			String password = console.next();

			try
			{
				String AES_Method = "AES/CBC/PKCS5Padding";
				Security.addProvider(new BouncyCastleProvider());
				
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
				
				//hash the user's password and make it to be the secret key to encrypt the private keys 
				MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
				messageDigest.update(user_password.getBytes());
				byte[] hashedPassword = messageDigest.digest();
				
				//generate a 16-bit salt
				SecureRandom random = new SecureRandom();
        		byte[] user_salt = new byte[16];
        		random.nextBytes(user_salt);

        		IvParameterSpec user_ivSpec = new IvParameterSpec(user_salt);

				//Actually encrypt the user's private key 
				Cipher ucipher = Cipher.getInstance(AES_Method, "BC");
				//create a shared key with the user's hashed password 
				SecretKey generated_skey = new SecretKeySpec(hashedPassword, "AES");
				ucipher.init(Cipher.ENCRYPT_MODE, generated_skey, user_ivSpec);
				
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
	            server_pub.add(kpn.getPublic());
	            //write server's public key to a file 
	            ObjectOutputStream sPubKOutStream = new ObjectOutputStream(new FileOutputStream("ServerPublic.bin"));
	            sPubKOutStream.writeObject(server_pub);
	            sPubKOutStream.close();
				
				//hash the password and make it to be the secret key to encrypt the private keys 
				MessageDigest messageDigest2 = MessageDigest.getInstance("SHA-256");
				messageDigest2.update(password.getBytes());
				byte[] hashedPassword2 = messageDigest2.digest();
				
				//generate salt for the server 
				byte[] server_salt = new byte[16];
        		random.nextBytes(server_salt);
        		IvParameterSpec server_ivSpec = new IvParameterSpec(server_salt);
				//Actually encrypt the user's private key 
				Cipher scipher = Cipher.getInstance(AES_Method, "BC");
				//create a shared key with the user's hashed password 
				SecretKeySpec generated_skey2 = new SecretKeySpec(hashedPassword2, "AES");
				scipher.init(Cipher.ENCRYPT_MODE, generated_skey2, server_ivSpec);
				
				byte[] key_data2 = (kpn.getPrivate()).getEncoded();
				byte[] encrypted_data2 = scipher.doFinal(key_data2);
				
				ArrayList<byte[]> server_priv_salt = new ArrayList<byte[]>();
				server_priv_salt.add(encrypted_data2);
				server_priv_salt.add(server_salt);
				//write server's encrypted private key to a file 
	            ObjectOutputStream sPrivKOutStream = new ObjectOutputStream(new FileOutputStream("ServerPrivate.bin"));
	            sPrivKOutStream.writeObject(server_priv_salt);
	            sPrivKOutStream.close();


				//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
				userList = new UserList();
				groupList = new GroupList();
				userList.addUser(username, kp.getPublic());
				groupList.addGroup("ADMIN", username);
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
			uOutStream.writeObject(my_gs.userList);
			gOutStream.writeObject(my_gs.groupList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
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
					uOutStream.writeObject(my_gs.userList);
					gOutStream.writeObject(my_gs.groupList);
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
}
