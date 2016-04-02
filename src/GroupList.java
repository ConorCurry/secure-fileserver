/* This list represents the users on the server */
import java.util.*;
import javax.crypto.*;
import java.security.*;
import org.bouncycastle.jce.provider.*;

	public class GroupList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7614180777L;
		private static final char[] blacklist = {'&', '+'};
		private Hashtable<String, Group> list = new Hashtable<String, Group>();
		
		public synchronized boolean addGroup(String groupname, String owner)
		{
			for(char invalidChar : blacklist) {
				if(groupname.indexOf(invalidChar) > 0) {
					return false;
				}
			}
		   	Group newGroup = new Group();
	   		list.put(groupname, newGroup);
   			//group creation requires an owner
	   		this.addOwner(owner, groupname);
		   	return true;
   		}
		
		public synchronized void deleteGroup(String groupname)
		{
			list.remove(groupname);
		}
		
		public synchronized boolean checkGroup(String groupname)
		{
			if(list.containsKey(groupname))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
        

		public synchronized List<String> getMembers(String groupname)
		{
			return list.get(groupname).getMember();
		}
		
		public synchronized boolean addMember(String user, String groupname) {
			for(char invalidChar : blacklist) {
				if(user.indexOf(invalidChar) > 0) {
					return false;
				}
			} 
		   	list.get(groupname).addMember(user);
	   		return true;
   		}
		
		public synchronized void removeMember(String user, String groupname) {
		    //NOTE: this function does not have the privilege to remove an owner
		    //add a new file key when a member is removed from the group
		    list.get(groupname).removeMember(user);
		    list.get(groupname).addNewKey();
		}
		
		public synchronized ArrayList<String> getGroupOwners(String groupname)
		{
			return list.get(groupname).getOwners();
		}
		
		public synchronized ArrayList<SecretKey> getFileKeys(String groupname)
		{
			return list.get(groupname).getFileKeys();
		}

		public synchronized void addOwner(String user, String groupname)
		{
			list.get(groupname).addOwner(user);
		}
		
		public synchronized void removeOwner(String user, String groupname)
		{
			list.get(groupname).removeOwner(user);
			
			//if there are no more owners, delete the group
			if(list.get(groupname).getOwners().isEmpty()) {
			    this.deleteGroup(groupname);
			}
		}
        
        public synchronized boolean checkOwnership(String user, String groupname)
        {
            if(list.get(groupname) != null)
            	return list.get(groupname).getOwners().contains(user);

            return false;
        }
		
		
	
	class Group implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = 6610772112L;
		private ArrayList<String> owners;
		private List<String> members;
		private ArrayList<SecretKey> file_keys; //created for file encryption/decryption
		
		public Group()
		{
			owners = new ArrayList<String>();
			members = new ArrayList<String>();
			file_keys = new ArrayList<SecretKey>();

			//create a new key to put into the file_keys list when a group is created 
			try
			{
				KeyGenerator key = KeyGenerator.getInstance("AES", "BC");
		        key.init(256, new SecureRandom());
		        file_keys.add(key.generateKey());
		    }
		    catch(Exception e)
		    {
		    	System.out.println("Fail to create a key when the group is created.");
		    }
		}

		public List<String> getMember()
		{
			return members;
		}
		
		public void addMember(String user) {
		    if(!members.contains(user)) {
		        members.add(user);
		    }
		}
		
		public void removeMember(String user) {
		    if(!members.isEmpty()) {
		        if(members.contains(user)) {
		            members.remove(members.indexOf(user));
		        }
	        }
		}
		
		public ArrayList<SecretKey> getFileKeys()
		{
			return file_keys;
		}

		public ArrayList<String> getOwners()
		{
			return owners;
		}
		
		public void addOwner(String user)
		{
			owners.add(user);
		}
		
		public void addNewKey()
		{
			//create a new key to put into the file_keys list when a member is deleted
			try
			{
				KeyGenerator key = KeyGenerator.getInstance("AES", "BC");
		        key.init(256, new SecureRandom());
		        file_keys.add(key.generateKey());
		    }
		    catch(Exception e)
		    {
		    	System.out.println("Fail to create a key when the group is created.");
		    }
		}

		public void removeOwner(String user)
		{
			if(!owners.isEmpty())
			{
				if(owners.contains(user))
				{
					owners.remove(owners.indexOf(user));
				}
			}
		}
		
	}
	
}	
