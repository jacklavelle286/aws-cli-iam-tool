import iam.users
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
                policy_choice = input("Select 1 to proceed with policy creation, 2 to list or delete local policy files, 3 to list policies within AWS or delete a specific policy within AWS, 4 to inspect a policy or 5 to return to the main menu: ").lower()
                if policy_choice == "1":
                    iam_policy.user_inputs = iam_policy.get_user_input_policy()
                    iam_policy.policy_file_name = iam_policy.create_iam_policy_file(iam_policy.user_inputs)
                    iam_policy.create_policy(iam_policy.policy_file_name)
                elif policy_choice == "2":
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
                        print("Which policy do you want to delete within AWS?\n")
                        print("listing policies in AWS...")
                        policy_list = iam_policy.list_policies_in_aws(arn=False, policy_type='Local')
                        for item in policy_list:
                            print(item)
                        policy_choice = input("Type which policy you would like to delete in AWS (Caution!! This will detach from any users, groups or roles currently using this policy and delete it: ")
                        if policy_choice not in policy_list:
                            print("policy is not found in AWS. ")
                            break
                        else:
                            iam_policy.delete_policy_remotely(policy_choice)
                            print(f"deleting {policy_choice}")
                            break
                elif policy_choice == "4":
                    print("Inpsecting policy...")
                    inspect_policy = input("Choose a policy to inspect: ")
                    policy_object = iam_policy.describe_policy(inspect_policy)
                    if policy_object is None:
                        print("Error when fetching policy document document. ")
                    elif not policy_object:
                        print("Policy document not found.")
                    else:
                        print(policy_object)
                    break
                elif policy_choice == "5":
                    print("Returning to main menu..")
                    break


        elif choice == '2':
            print("Building IAM Users.... ")
            while True:
                users_choice = input("Select 1 to proceed with IAM user creation, 2 to interact with an existing IAM User, 3 to list IAM users or 4 to delete a iam user. Press anything else to return to the main menu: \n")
                if users_choice not in ['1', '2', '3', '4']:
                    print("Exiting to main menu.. ")
                    break
                elif users_choice == "1":
                    print("Creating user..")
                    username = input("Enter a username for your user: ")
                    iam_user_creation = users.create_iam_user(username)
                    if iam_user_creation:
                        print(iam_user_creation)
                    elif iam_user_creation is None:
                        print(iam_user_creation)
                elif users_choice == "2":
                    print("interacting with iam users..")
                    username = input("Enter the name of the IAM user you'd like to work with: ")
                    print(f"You chose {username}")
                    current_list_of_users = users.list_iam_users()
                    if username not in current_list_of_users:
                        print("Your user does not exist, here is the list of users:")
                        for user in current_list_of_users:
                            print(f"- {user}")
                    while True:
                        list_of_users = users.list_iam_users()
                        if username not in list_of_users:
                            print("IAM User doesn't exist, try again.")
                            print("The following users available in this account are: ")
                            for user in list_of_users:
                                print(f"- {user}")
                        else:
                            users_choice = input(f"\nDo you want to: \n(1) List Policies attached to {username} \n(2) Add Polices \n(3) Remove Policies \n(4) Change password \n(5) List current Credentials associated with {username} \n(6) revoke credentials for {username} \n(7) Rotate access keys for user \n(8) Delete {username} \nPress anything else to quit: \n")
                            if users_choice not in ['1', '2', '3', '4', '5', '6', '7', '8']:
                                print("Exiting..")
                                break
                            elif users_choice == "1":
                                print("Listing IAM attached policies...")
                                list_of_managed_policies = users.list_attached_managed_user_policies(username=username)

                                if isinstance(list_of_managed_policies, str):
                                    print(list_of_managed_policies)
                                elif list_of_managed_policies:  # Non-empty list
                                    print("\nList of Managed Policies:\n")
                                    for m_policy in list_of_managed_policies:
                                        print(f"- {m_policy}")

                                print("Listing IAM inline policies...")
                                list_of_inline_policies = users.list_attached_inline_user_policies(username=username)

                                if isinstance(list_of_inline_policies, str):
                                    print(list_of_inline_policies)
                                elif list_of_inline_policies:
                                    for i_policy in list_of_inline_policies:
                                        print(f"- {i_policy}")


                                inspect_policy = input("Do you want to inspect a policy? enter a name and you can view the policy (note doesn't work for inline policies currently): ")
                                policy_object = iam_policy.describe_policy(inspect_policy)
                                if policy_object is None:
                                    print("Error when fetching policy document document. ")
                                elif not policy_object:
                                    print("Policy document not found.")
                                else:
                                    print(policy_object)




                            elif users_choice == "2":
                                print("Adding policies")
                                attach_choice = input(
                                    "Enter 'attach' to specify a valid ARN, or type 'create' to create a new policy: ")
                                if attach_choice.lower() == "attach":
                                    arn = input("Enter a valid ARN: ")
                                    valid_arns = iam_policy.list_policies_in_aws(arn=True, policy_type='All')
                                    print(f"Checking against all {len(valid_arns)} policies in your account to see if it exists...")
                                    if arn not in valid_arns:
                                        print("Invalid ARN: doesn't exist within your account.")
                                    else:
                                        is_attached_already = users.list_attached_managed_user_policies(
                                            username=username)
                                        policy_name = arn.split('/')[-1]
                                        # Check if policy name is in the list of already attached policies
                                        if policy_name in is_attached_already:
                                            print("Policy already attached!")
                                            print(f"Currently attached are as follow policies: ")
                                            for item in is_attached_already:
                                                print(f"- {item}")
                                        else:
                                            attach_attempt = users.attach_user_policy(username=username, policy_arn=arn)
                                            print(attach_attempt)
                                elif attach_choice.lower() == "create":
                                    print("Creating new policy... ")
                                    iam_policy.user_inputs = iam_policy.get_user_input_policy()
                                    iam_policy.policy_file_name = iam_policy.create_iam_policy_file(
                                        iam_policy.user_inputs)
                                    created_policy = iam_policy.create_policy(iam_policy.policy_file_name)
                                    if created_policy:
                                        policy_arn = created_policy  # ARN returned by create_policy
                                        print(f"Attaching {policy_arn}...")
                                        attach_response = users.attach_user_policy(username=username,
                                                                                   policy_arn=policy_arn)
                                        print(attach_response)
                                    else:
                                        print("Policy creation failed; cannot attach.")




                            elif users_choice == "3":
                                print("Removing policies")
                                all_policies = input("If you want to delete all policies type 'all' or type 'arn' to input a specific arn: ")
                                if all_policies.lower() == "all":
                                    users.delete_policies(username=username)
                                elif all_policies.lower() == "arn":
                                    specific_arn = input("List a specific policy arn: ")
                                    list_of_policies_attached = users.list_attached_managed_user_policies(username) # returns non arns
                                    for policy in list_of_policies_attached:
                                        policy_arn = iam_policy.get_iam_policy_arn(new_policy=policy)
                                        if policy_arn == specific_arn:
                                            detach_result = users.detach_user_policy(username=username, policy_arn=policy_arn)
                                            print(detach_result)


                            elif users_choice == "4":
                                print("Changing password")

                            elif users_choice == "5":
                                print("listing current credentials")

                            elif users_choice == "6":
                                print("Revoking Credentials..")

                            elif users_choice == "7":
                                print("Rotating Keys..")


                            elif users_choice == "8":
                                print(f"Deleting {username}...\n")
                                iam_user_delete_response = iam.users.delete_iam_user(username)
                                print(iam_user_delete_response)
                                break





                elif users_choice == "4":
                    user_to_delete = input("Enter the name of the user you want to delete: ").lower()
                    users.delete_iam_user(user_to_delete)

        elif choice == "q":
            print("Exiting the programme..")
            exit()

if __name__ == "__main__":
    main()





