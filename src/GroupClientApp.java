import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;

public class GroupClientApp
{
	private static GroupClient groupClient;
	private static Scanner input;
	private static int times = 1;
	private static UserToken token;
	private static int choice;

	public static void main(String[] args)
	{
	    //create a new group client 
	    groupClient = new GroupClient();
	    input = new Scanner(System.in);
		
	    //connect to the group server 
		int port = -1;
		if(args.length == 0)
		{
			port = 8765; //default value	
		}
		else
		{
			try{
				port = Integer.parseInt(args[0]);
			}
			catch(Exception e)
			{
				System.out.println("Unable to get vaid port number. Exiting.......");
				System.exit(0);
			}
		}
		groupClient.connect("localhost", port);
		while(true)
		{
			printMainMenu();
			//just to distinguish the first operation from other ones. 
			if(times == 1) times++;
		}
	}

	public static void printMainMenu()
	{
		
		//if the user just open the application. 
		if(times == 1)
		{
			System.out.println("------------Welcome to CS1653 Group-Based File Sharing application------------\n");
			System.out.println("Please enter your username:");
			String username = input.nextLine();
			token = groupClient.getToken(username); //get a token for this user
		}
		else
		{	
			System.out.println("\t\t\tMain Menu: ");
			System.out.println("------------Please choose the number of what you want to do from the following options-------\n");
			System.out.println("1. Create User");
			System.out.println("2. Delete User");
			System.out.println("3. Create Group");
			System.out.println("4. Delete Group");
			System.out.println("5. Add User To Group");
			System.out.println("6. Delete User From Group");
			System.out.println("7. List members of a group");
			System.out.println("8. Disconnect from the server and exit the application");
			System.out.print("\nPlease enter your choice: ");

			//check whether the choice is valid 
			while(true){
				try
				{
					choice = input.nextInt();
				}
				catch(Exception e)
				{
					System.out.println("Sorry, Your choice is not valid, please enter a valid number.");
					continue;
				}
				if(choice < 1 && choice > 8)
				{
					System.out.println("Sorry, Your choice is not valid, please enter a valid number.");
				}
				else break;
			}
			input.nextLine();

			switch(choice){
				case 1:
					optionOne();
					break;

				case 2:
					optionTwo();
					break;
				
				case 3:
					optionThree();
					break;
				
				case 4:
					optionFour();
					break;

				case 5:
					optionFive();
					break;

				case 6:
					optionSix();
					break;

				case 7:
					optionSeven();
					break;	

				default:
					optionEight();
					break;
			}
		}
	}

	public  static void optionOne()
	{
		System.out.print("You have chose to create user. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			System.out.print("Please Enter the Username you would like to create: ");
			String createdUserName = input.nextLine();
			if(groupClient.createUser(createdUserName, token))
				System.out.println("Congratulations! You have created user " + createdUserName + " successfully!");
			else
				System.out.println("Sorry. You fail to create this user. Please try other options.");
		}
		System.out.println("Going back to main menu............................................\n");
	}

	public static void optionTwo()
	{
		System.out.print("You have chose to delete user. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			System.out.print("Please Enter the Username you would like to delete: ");
			String deletedUserName = input.nextLine();
			if(groupClient.deleteUser(deletedUserName, token))
				System.out.println("Congratulations! You have deleted user " + deletedUserName + " successfully!");
			else
				System.out.println("Sorry. You fail to delete this user. Please try other options.");
		}
		System.out.println("Going back to main menu............................................\n");
	}

	public static void optionThree()
	{
		System.out.print("You have chose to create a new group. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			System.out.print("Please Enter the group name you would like to create: ");
			String groupName = input.nextLine();
			if(groupClient.createGroup(groupName, token))
				System.out.println("Congratulations! You have created the new group " + groupName + " successfully!");
			else
				System.out.println("Sorry. You fail to create this group. Please try other options.");
		}
		System.out.println("Going back to main menu............................................\n");
	}

	public static void optionFour()
	{
		System.out.print("You have chose to delete a new group. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			System.out.print("Please Enter the group name you would like to delete: ");
			String groupName = input.nextLine();
			if(groupClient.deleteGroup(groupName, token))
				System.out.println("Congratulations! You have deleted the new group " + groupName + " successfully!");
			else
				System.out.println("Sorry. You fail to delete this group. Please try other options.");
		}
		System.out.println("Going back to main menu............................................\n");
	}

	public static void optionFive()
	{
		System.out.print("You have chose to add a user to a group. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			System.out.print("Please Enter the Username to be added: ");
			String userName = input.nextLine();
			System.out.print("Please Enter the group name you would like to add: ");
			String groupName = input.nextLine();
			if(groupClient.addUserToGroup(userName, groupName, token))
				System.out.println("Congratulations! You have added the user " + userName +" to the group " + groupName + " successfully!");
			else
				System.out.println("Sorry. You fail to add this user to the group. Please try other options.");

		}
		System.out.println("Going back to main menu............................................\n");
	}

	public static void optionSix()
	{
		System.out.print("You have chose to delete a user from a group. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			System.out.println();
			System.out.print("Please Enter the Username to be deleted: ");
			String userName = input.nextLine();
			System.out.print("Please Enter the group name which the user belongs to: ");
			String groupName = input.nextLine();
			if(groupClient.deleteUserFromGroup(userName, groupName, token))
				System.out.println("\nCongratulations! You have deleted the user " + userName +" from the group " + groupName + " successfully!");
			else
				System.out.println("\nSorry. You fail to delete this user from the group. Please try other options.");

		}
		System.out.println("Going back to main menu............................................\n");
	}

	public static void optionSeven()
	{
		System.out.print("You have chose to list all the members of the group. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			System.out.println();
			System.out.print("Please Enter the group name which you would like to see all the members: ");
			String groupName = input.nextLine();
			List<String> members = new ArrayList<String>(groupClient.listMembers(groupName, token));
			if(members != null)
			{
				System.out.println("\nCongratulations! You have fetched all the memers from the group " + groupName + " successfully!");
				System.out.println("Start to list");
				for(int i = 0; i < members.size(); i++)
				{
					System.out.println(""+ (i+1) + ". " + members.get(i));
				}
			}
			else
				System.out.println("Sorry. You fail to delete this user from the group. Please try other options.");
		}
		System.out.println("Going back to main menu............................................\n");
	}

	public static void optionEight()
	{
		System.out.print("You have chose to list all the members of the group. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			groupClient.disconnect();
			System.out.println("You have disconnected from the server successfully! Exiting the application!");
			System.exit(0);
		}
		System.out.println("Going back to main menu............................................\n");
	}
}