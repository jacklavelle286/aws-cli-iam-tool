from iam import iam_policy, users
from iam import iam_client

# Main Program Execution for iam_policy.py

def main():
    print(r"""
            __          __   _____     _____              __  __     _____            _     _                        __          __
     /\     \ \        / /  / ____|   |_   _|     /\     |  \/  |   |  __ \          | |   | |                       \ \        / /
    /  \     \ \  /\  / /  | (___       | |      /  \    | \  / |   | |__) |  _   _  | |_  | |__     ___    _ __      \ \  /\  / /   _ __    __ _   _ __    _ __     ___   _ __
   / /\ \     \ \/  \/ /    \___ \      | |     / /\ \   | |\/| |   |  ___/  | | | | | __| | '_ \   / _ \  | '_ \      \ \/  \/ /   | '__|  / _` | | '_ \  | '_ \   / _ \ | '__|
  / ____ \     \  /\  /     ____) |    _| |_   / ____ \  | |  | |   | |      | |_| | | |_  | | | | | (_) | | | | |      \  /\  /    | |    | (_| | | |_) | | |_) | |  __/ | |
 /_/    \_\     \/  \/     |_____/    |_____| /_/    \_\ |_|  |_|   |_|       \__, |  \__| |_| |_|  \___/  |_| |_|       \/  \/     |_|     \__,_| | .__/  | .__/   \___| |_|
                                                                               __/ |                                                               | |     | |
                                                                              |___/                                                                |_|     |_|
""")

    print("Welcome to the PIAM Python Wrapper")
    while True:
        choice = input("Do you want to work with IAM Policies (1), Users (2), Roles (3) or Groups? (4): (1,2,3 or 4) or press 'q' to quit the programme. ").lower()
        if choice == "1":
            print("Building IAM Polices..")
            while True:
                policy_choice = input("Select 1 to proceed with policy creation, 2 to list or delete local policy files, 3 to list policies within AWS or delete a specific policy within AWS, or 4 to return to the main menu: ").lower()
                if policy_choice == "1":
                    iam_policy.user_inputs = iam_policy.get_user_input_policy()
                    iam_policy.policy_file_name = iam_policy.create_iam_policy_file(iam_policy.user_inputs)
                    iam_policy.create_policy(iam_policy.policy_file_name)
                elif policy_choice == "2":
                    while True:
                        local_deletion_choice = input("Either name a local file by name to delete it, or select * to remove all local policy files: ")
                        policy_list = iam_policy.list_local_policy_files()
                        if local_deletion_choice != "*" and local_deletion_choice not in policy_list:
                            print("Invalid choice - try again - either not a wildcard, or policy doesn't exist locally.")
                            list_option = input("Press 'l' if you want to list the policies locally: ").lower()
                            if list_option != "l":
                                pass
                            else:
                                policies = iam_policy.list_local_policy_files()
                                print("Local policies: \n")
                                for item in policies:
                                    print(item)
                        elif local_deletion_choice == "*":
                            print("Deleting all locally stored IAM policy files...")
                            iam_policy.delete_all_policies_locally()
                            break
                        else:
                            print(f"Deleting {local_deletion_choice}...")
                            iam_policy.delete_policy_file(local_deletion_choice)
                            break
                elif policy_choice == "3":
                    print("Listing or deleting policies in AWS...")
                    while True:
                        deletion_choice = input("Which policy do you want to delete within AWS? Press 'l' to list all policies customer managed policies in AWS: ")
                        if deletion_choice == "l":
                            print("listing policies in AWS...")
                            policy_list = iam_policy.list_policies_in_aws()
                            for item in policy_list:
                                print(item)
                        else:
                            policy_list = iam_policy.list_policies_in_aws()
                            if policy_choice not in policy_list:
                                print("policy is not found in AWS. ")
                                break
                            else:
                                iam_policy.delete_policy_remotely(deletion_choice)
                                print(f"deleting {deletion_choice}")
                                break
                elif policy_choice == "4":
                    print("Returning to main menu..")
                    break


        elif choice == '2':
            print("Building IAM Users.... ")
            while True:
                users_choice = input("Select 1 to proceed with IAM user creation, 2 to interact with an existing IAM User, 3 to list IAM users or 4 to delete a iam user. Press anything else to return to the main menu: ")
                if users_choice not in ['1', '2', '3', '4']:
                    print("Exiting to main menu.. ")
                    break
                else:
                    print("Processing choice..")
                if users_choice == "1":
                    print("Creating user..")
                elif users_choice == "2":
                    print("interacting with iam users..")
                    username = input("Enter the name of the IAM user you'd like to work with: ").lower()
                    print(f"You chose {username}")
                    list_of_users = users.list_iam_users()
                    if username not in list_of_users:
                        print("IAM User doesn't exist, try again.")
                        break
                    user_choice = input(f"Do you want to: \n(1) List Policies attached to {username} \n(2) Add Polices \n(3) Remove Policies \n(4) Change password \n(5) List current Credentials associated with {username} \n(6) revoke credentials for {username} \n(7) Rotate access keys for user \n(8) Delete {username} \nPress anything else to quit.")
                    print(user_choice) # main bit to build out
                elif users_choice == "3":
                    print("Listing IAM Users..")
                    list_of_users = users.list_iam_users()
                    if list_of_users:
                        print("IAM Users:")
                        for user in list_of_users:
                            print(f"- {user}")
                    else:
                        print("No IAM users found.")

                elif users_choice == "4":
                    user_to_delete = input("Enter the name of the user you want to delete: ").lower()
                    users.delete_iam_user(user_to_delete)

                else:
                    break
        elif choice == "q":
            print("Exiting the programme..")
            exit()

if __name__ == "__main__":
    main()





