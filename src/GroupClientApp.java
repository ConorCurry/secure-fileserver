import java.util.Scanner;

public class GroupClientApp
{
	private GroupClient groupClient;
	private Scanner input;
	private int times = 1;
	private UserToken token;
	private int choice;

	public static void main(String[] args)
	{
	    //create a new group client 
	    groupClient = new GroupClient();
	    input = new Scanner(System.in);
		
	    //connect to the group server 
		int port;
		if(args.length == 0
		{
			port = GroupSever.SERVER_PORT;	
		}
		else
		{
			port = Integer.ParseInt(args[0]);
		}
		groupClient.connect("ALPHA", port);
		while(true)
		{
			printMainMenu();
			//just to distinguish the first operation from other ones. 
			if(times == 1) times++;
		}
	}

	public void printMainMenu()
	{
		
		//if the user just open the application. 
		if(times == 1)
		{
			System.out.println("------------Welcome to CS1653 Group-Based File Sharing application------------\n");
			System.out.println("Please enter your username:")
			String username = input.nextLine();
			token = groupClient.getToken(username); //get a token for this user
		}
		else
		{	
			System,out.println("\t\t\tMain Menu: ");
			System.out.println("------------Please choose the number of what you want to do from the following options-------\n");
			System.out.println("1. Create User");
			System.out.println("2. Delete User");
			System.out.println("3. Create Group");
			System.out.println("4. Delete Group");
			System.out.println("5. Add User To Group");
			System.out.println("6. Delete User From Group");
			System.out.println("7. List members of a group");
			System.out.println("\nPlease enter your choice: ");

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
			}
		}
	}

	public void optionOne()
	{
		System.out.print("You have chose to create user. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			input.nextLine();
			System.out.println();
			System.out.print("Please Enter the Username you would like to create: ");
			String createdUserName = input.nextLine();
			if(groupClient.createUser(createdUserName, token))
				System.out.println("Congratulations! You have created user " + createdUserName + "successfully!");
			else
				System.out.println("Sorry. You fail to create this user. Please try other options.");

			System.out.println("Going back to main menu............................................\n");
		}
	}

	public void optionTwo()
	{
		System.out.print("You have chose to delete user. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			input.nextLine();
			System.out.println();
			System.out.print("Please Enter the Username you would like to delete: ");
			String deletedUserName = input.nextLine();
			if(groupClient.createUser(deletedUserName, token))
				System.out.println("Congratulations! You have deleted user " + deletedUserName + "successfully!");
			else
				System.out.println("Sorry. You fail to delete this user. Please try other options.");

			System.out.println("Going back to main menu............................................\n");
		}
	}

	public void optionThree()
	{
		System.out.print("You have chose to create a new group. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			input.nextLine();
			System.out.println();
			System.out.print("Please Enter the group name you would like to create: ");
			String groupName = input.nextLine();
			if(groupClient.createGroup(groupName, token))
				System.out.println("Congratulations! You have created the new group" + groupName + "successfully!");
			else
				System.out.println("Sorry. You fail to create this group. Please try other options.");

			System.out.println("Going back to main menu............................................\n");
		}
	}

	public void optionFour()
	{
		System.out.print("You have chose to delete a new group. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			input.nextLine();
			System.out.println();
			System.out.print("Please Enter the group name you would like to delete: ");
			String groupName = input.nextLine();
			if(groupClient.deleteGroup(groupName, token))
				System.out.println("Congratulations! You have deleted the new group" + groupName + "successfully!");
			else
				System.out.println("Sorry. You fail to delete this group. Please try other options.");

			System.out.println("Going back to main menu............................................\n");
		}
	}

	public void optionFive()
	{
		System.out.print("You have chose to add a user to a group. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			input.nextLine();
			System.out.println();
			System.out.print("Please Enter the Username to be added: ");
			String userName = input.nextLine();
			System.out.print("Please Enter the group name you would like to add: ");
			String groupName = input.nextLine();
			if(groupClient.addUserToGroup(userName, groupName, token))
				System.out.println("Congratulations! You have added the user " + userName +" to the group" + groupName + "successfully!");
			else
				System.out.println("Sorry. You fail to add this user to the group. Please try other options.");

			System.out.println("Going back to main menu............................................\n");
		}
	}

	public void optionSix()
	{
		System.out.print("You have chose to delete a user from a group. Press 1 to continue. Press other number to go back to main menu: ");
		choice = input.nextInt();
		input.nextLine();
		if(choice == 1)
		{
			input.nextLine();
			System.out.println();
			System.out.print("Please Enter the Username to be deleted: ");
			String userName = input.nextLine();
			System.out.print("Please Enter the group name which the user belongs to: ");
			String groupName = input.nextLine();
			if(groupClient.deleteUserFromGroup(userName, groupName, token))
				System.out.println("Congratulations! You have deleted the user " + userName +" from the group" + groupName + "successfully!");
			else
				System.out.println("Sorry. You fail to delete this user from the group. Please try other options.");

			System.out.println("Going back to main menu............................................\n");
		}
	}

	public void optionSeven()
	{

	}

}