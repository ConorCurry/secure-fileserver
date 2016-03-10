/* This list represents the users on the server */
import java.util.*;


	public class UserList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private static final char[] blacklist = {'&', '+'};
		private Hashtable<String, User> list = new Hashtable<String, User>();
		
		public synchronized boolean addUser(String username)
		{
			for(char invalidChar : blacklist) {
				if(username.indexOf(invalidChar) > 0) {
					return false;
				}
			}
		   	User newUser = new User();
	   		list.put(username, newUser);
   			return true;
		}
		
		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}
		
		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		/* This method is used to get the groups that user belongs to */
		public synchronized ArrayList<String> getUserGroups(String username) 
		{
			return list.get(username).getGroups();
		}
		
		/* get the groups owned by the user */
		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}
		
		/* add a new group to a user */
		public synchronized boolean addGroup(String user, String groupname)
		{
			for(char invalidChar : blacklist) {
				if(groupname.indexOf(invalidChar) > 0) {
					return false;
				}
			}
			list.get(user).addGroup(groupname);
			return true;
		}
		
		/* remove a group from a user */
		public synchronized void removeGroup(String user, String groupname)
		{
			list.get(user).removeGroup(groupname);
		}
		
		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
		}
		
		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}

	
	class User implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		
		public User()
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}
		
		public ArrayList<String> getGroups()
		{
			return groups;
		}
		
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}
		
		public void addGroup(String group)
		{
			groups.add(group);
		}
		
		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}
		
		public void addOwnership(String group)
		{
			ownership.add(group);
		}
		
		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}
		
	}
}	
