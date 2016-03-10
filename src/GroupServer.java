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

			try
			{
				//generate a key pair for the first user
				Hashtable <String, KeyPair> user_keypair = new Hashtable <String, KeyPair> ();
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            	kpg.initialize(3072, new SecureRandom());
           	 	KeyPair kp = kpg.genKeyPair();
            	user_keypair.put(username, kp);
	            PublicKey usrPubKey = kp.getPublic();
	            
	            //wrote the updated table back to the file 
	            ObjectOutputStream uKOutStream;
	            uKOutStream = new ObjectOutputStream(new FileOutputStream("UserKeyPair.bin"));
	            uKOutStream.writeObject(user_keypair);
				
	            //generate a key pair for the server
	            KeyPairGenerator kpgn = KeyPairGenerator.getInstance("RSA", "BC");
	            kpgn.initialize(3072, new SecureRandom());
	            KeyPair kpn = kpgn.genKeyPair();

	            //write server's public key to a file 
	            ObjectOutputStream sKOutStream;
	            sKOutStream = new ObjectOutputStream(new FileOutputStream("ServerPublic.bin"));
	            sKOutStream.writeObject(kp.getPublic());
			
				//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
				userList = new UserList(kpn);
				groupList = new GroupList();
				userList.addUser(username, usrPubKey);
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
				thread = new GroupThread(sock, this);
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
