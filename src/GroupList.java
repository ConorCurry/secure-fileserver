/* This list represents the users on the server */
import java.util.*;


	public class GroupList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7614180777L;
		private Hashtable<String, Group> list = new Hashtable<String, Group>();
		
		public synchronized void addGroup(String groupname, String owner)
		{
			Group newGroup = new Group();
			list.put(groupname, newGroup);
			//group creation requires an owner
			this.addOwner(owner, groupname);
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
		
		public synchronized void addMember(String user, String groupname) {
		    list.get(groupname).addMember(user);
		}
		
		public synchronized void removeMember(String user, String groupname) {
		    //NOTE: this function does not have the privilege to remove an owner
		    list.get(groupname).removeMember(user);
		}
		
		public synchronized ArrayList<String> getGroupOwners(String groupname)
		{
			return list.get(groupname).getOwners();
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
		
		public Group()
		{
			owners = new ArrayList<String>();
			members = new ArrayList<String>();
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
		
		public ArrayList<String> getOwners()
		{
			return owners;
		}
		
		public void addOwner(String user)
		{
			owners.add(user);
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
