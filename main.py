from iam import policy, users


# Main Program Execution for policy.py

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

    print("Welcome to the IAM Python Wrapper")
    while True:
        choice = input("Do you want to work with IAM Policies (1), Users (2), Roles (3) or Groups? (4): (1,2,3 or 4) or press 'q' to quit the programme. ").lower()
        if choice == "1":
            print("Building IAM Polices..")
            while True:
                policy_choice = input("Select 1 to proceed with policy creation, 2 to list or delete local policy files, 3 to list policies within AWS or delete a specific policy within AWS, or 4 to return to the main menu: ").lower()
                if policy_choice == "1":
                    policy.user_inputs = policy.get_user_input_policy()
                    policy.policy_file_name = policy.create_iam_policy_file(policy.user_inputs)
                    policy.create_policy(policy.policy_file_name)
                elif policy_choice == "2":
                    while True:
                        local_deletion_choice = input("Either name a local file by name to delete it, or select * to remove all local policy files: ")
                        policy_list = policy.list_local_policy_files()
                        if local_deletion_choice != "*" and local_deletion_choice not in policy_list:
                            print("Invalid choice - try again - either not a wildcard, or policy doesn't exist locally.")
                            list_option = input("Press 'l' if you want to list the policies locally: ").lower()
                            if list_option != "l":
                                pass
                            else:
                                policies = policy.list_local_policy_files()
                                print("Local policies: \n")
                                for item in policies:
                                    print(item)
                        elif local_deletion_choice == "*":
                            print("Deleting all locally stored IAM policy files...")
                            policy.delete_all_policies_locally()
                            break
                        else:
                            print(f"Deleting {local_deletion_choice}...")
                            policy.delete_policy_file(local_deletion_choice)
                            break
                elif policy_choice == "3":
                    print("Listing or deleting policies in AWS...")
                    while True:
                        deletion_choice = input("Which policy do you want to delete within AWS? Press 'l' to list all policies customer managed policies in AWS: ")
                        if deletion_choice == "l":
                            print("listing policies in AWS...")
                            policy_list = policy.list_policies_in_aws()
                            for item in policy_list:
                                print(item)
                        else:
                            policy_list = policy.list_policies_in_aws()
                            if policy_choice not in policy_list:
                                print("policy is not found in AWS. ")
                                break
                            else:
                                policy.delete_policy_remotely(deletion_choice)
                                print(f"deleting {deletion_choice}")
                                break
                elif policy_choice == "4":
                    print("Returning to main menu..")
                    break


        elif choice == '2':
            print("Building IAM Users.... ")
            while True:
                users_choice = input("Select 1 to proceed with IAM user creation, 2 to interact with an existing IAM User, 3 to list IAM Users, 4 to delete IAM Users, or 5 to return to the main menu: ")
                if users_choice == "1":
                    print("Creating user..")
                elif users_choice == "2":
                    print("interacting with iam users..")
                elif users_choice == "3":
                    print("Listing iam users..")
                    list_of_users = users.list_iam_users()
                    print("List of users: ")
                    for user in list_of_users:
                        print(user)
                    while True:
                        policies_attached = input("Do you want to see the attached policies of any users? (y/n):  ").lower()
                        if policies_attached != "y" and policies_attached != "n":
                            print("Invalid option. ")
                        elif policies_attached == "y":
                            while True:
                                user_for_list_policies = input("Enter which user you want to see the policies for: ")
                                if user_for_list_policies not in list_of_users:
                                    print("Invalid option, user does not exist")
                                else:
                                    print(f"listing polices for {user_for_list_policies}")
                                    inline_policies_attached = users.list_attached_user_policies(username=user_for_list_policies,managed=False)
                                    for i_policy in inline_policies_attached:
                                        print(f"Inline Policies attached: {i_policy}")
                                    managed_policies_attached = users.list_attached_user_policies(username=user_for_list_policies,managed=True)
                                    for m_policy in managed_policies_attached:
                                        print(f"Managed Policies attached: {m_policy}")
                                    break

                        elif policies_attached == "n":
                            break

                elif users_choice == "4":
                    user_to_delete = input("Enter the name of the user you want to delete: ").lower()
                    users.delete_iam_user(user_to_delete)


        elif choice == "q":
            print("Exiting the programme..")
            exit()

if __name__ == "__main__":
    main()



