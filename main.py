from operator import indexOf

from iam import iam_policy, users
from iam import iam_client
import getpass

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
        choice = input("Do you want to work with IAM Policies (1), Users (2), Roles (3) or Groups? (4) or Admin (5): (1,2,3, 4 or 5) or press 'q' to quit the programme. ").lower()
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
                    if iam_user_creation is None:
                        print("Didn't enter any name, exiting..")
                        break
                    if iam_user_creation:
                        print(iam_user_creation)
                    elif iam_user_creation is None:
                        print(iam_user_creation)
                    add_policy = input("Would you like to add a policy to your user?: (y or anything else to skip): ").lower()
                    if add_policy != "y":
                        print("Invalid option.")
                    else:
                        print("Adding policies")
                        attach_choice = input("Enter 'attach' to specify a valid ARN, or type 'create' to create a new policy: ")
                        if attach_choice.lower() == "attach":
                            arn = input("Enter a valid ARN: ")
                            valid_arns = iam_policy.list_policies_in_aws(arn=True, policy_type='All')
                            print(
                                f"Checking against all {len(valid_arns)} policies in your account to see if it exists...")
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

                elif users_choice == "2":
                    print("interacting with iam users..")
                    username = input("Enter the name of the IAM user you'd like to work with: ")
                    print(f"You chose {username}")
                    current_list_of_users = users.list_iam_users()
                    if username not in current_list_of_users:
                        print("Your user does not exist, here is the list of users:")
                        for user in current_list_of_users:
                            print(f"- {user}")
                    else:
                        while True:
                            users_choice = input(f"\nDo you want to: \n(1) List Policies attached to {username} \n(2) List Groups {username} is in \n(3) Add {username} to a group \n(4) Remove {username} from a group \n(5) Add Polices to {username}\n(6) Remove Policies from {username}\n(7) Change password for {username} \n(8) List credentials associated with {username} \n(9) revoke credentials for {username} \n(10) Rotate access keys for {username} \n(11) Delete {username} \nPress anything else to quit: \n")
                            if users_choice not in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']:
                                print("Exiting..")
                                break
                            elif users_choice == "1":
                                print("Listing IAM attached policies...")
                                list_of_managed_policies = users.list_attached_managed_user_policies(username=username)

                                if isinstance(list_of_managed_policies, str):
                                    print(list_of_managed_policies)
                                elif list_of_managed_policies:
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
                                print("listing groups")
                                list_of_groups = users.list_groups_for_user(username)
                                if isinstance(list_of_groups, str):
                                    print(list_of_groups)
                                elif list_of_groups:
                                    print("Groups: ")
                                    for group in list_of_groups:
                                        print(f"-{group}")

                            elif users_choice == "3":
                                print("Adding to group...")



                            elif users_choice == "4":
                                print(f"Removing {username} from groups....")
                                # check groups user is in
                                groups_for_user = users.list_groups_for_user(username)
                                if isinstance(groups_for_user, str):
                                    print(groups_for_user)
                                elif groups_for_user:
                                    for group in groups_for_user:
                                        print(f"Removing {username} from {group}")


                            elif users_choice == "5":
                                print("Adding policies")
                                attach_choice = input("Enter 'attach' to specify a valid ARN, or type 'create' to create a new policy: ")
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




                            elif users_choice == "6":
                                print("Removing policies")
                                all_policies = input("If you want to delete all policies type 'all' or type 'arn' to input a specific arn: ")
                                if all_policies.lower() == "all":
                                    # detach managed polices
                                    list_of_managed_policies = users.list_attached_managed_user_policies(username)
                                    if isinstance(list_of_managed_policies, str):
                                        print(list_of_managed_policies)
                                    elif list_of_managed_policies:
                                        for policy in list_of_managed_policies:
                                            # get arn of each policy
                                            policy_arn = iam_policy.get_iam_policy_arn(new_policy=policy)
                                            users.detach_user_policy(username=username, policy_arn=policy_arn)
                                            print(f"Detached {policy_arn} from {username}")
                                    # delete inline policies
                                    # for policy in inline policy, call delete user policy function
                                    list_of_inline_policies = users.list_attached_inline_user_policies(username=username)
                                    if isinstance(list_of_inline_policies, str):
                                        print(list_of_inline_policies)
                                    elif list_of_inline_policies:
                                        for policy in list_of_inline_policies:
                                            print(f"Deleting inline policy: {policy}")
                                            delete_inline_policies = users.delete_user_policy(username=username, policy_name=policy)
                                            if delete_inline_policies:
                                                print(delete_inline_policies)


                                elif all_policies.lower() == "arn":
                                    specific_arn = input("List a specific policy arn: ")
                                    list_of_policies_attached = users.list_attached_managed_user_policies(username) # returns non arns
                                    for policy in list_of_policies_attached:
                                        policy_arn = iam_policy.get_iam_policy_arn(new_policy=policy)
                                        if policy_arn == specific_arn:
                                            detach_result = users.detach_user_policy(username=username, policy_arn=policy_arn)
                                            print(detach_result)



                            elif users_choice == "7":
                                print("Changing password")
                                password = getpass.getpass("Enter your password: ")
                                change_password = users.change_password(username, password)
                                print(change_password)

                            elif users_choice == "8":
                                print("listing credentials...")
                                creds_options = ["access key", "certificate", "public ssh key", "service credentials","mfa devices"]
                                creds_options_string = ", ".join(creds_options)
                                creds_choice = input(f"Which type of credentials would you like to list? You can choose from the following: {creds_options_string}: ")
                                if creds_choice.lower() not in creds_options:
                                    print(f"You chose {creds_choice}: Invalid option. ")
                                elif creds_choice.lower() == "access key":
                                    print("listing access keys..")
                                    access_keys = users.list_access_keys(username)
                                    if isinstance(access_keys, str):
                                        print(access_keys)
                                    elif access_keys:
                                        print("Access keys: ")
                                        for key in access_keys:
                                            print(f"- {key}")
                                elif creds_choice == "certificate":
                                    print("listing certificates..")
                                    certs_list = users.list_certificate_ids(username)
                                    if isinstance(certs_list, str):
                                        print(certs_list)
                                    elif certs_list:
                                        print("Certificates attached: ")
                                        for cert in certs_list:
                                            print(f"- {cert}")
                                elif creds_choice == "public ssh key":
                                    print("listing SSH Keys.. ")
                                    ssh_key_list = users.list_public_ssh_keys(username)
                                    if isinstance(ssh_key_list, str):
                                        print(ssh_key_list)
                                    elif ssh_key_list:
                                        print("list Of SSH Keys: ")
                                        for key in ssh_key_list:
                                            print(f"- {key}")
                                elif creds_choice == "service credentials":
                                    print("listing Service credentials.. ")
                                    service_cred_list = users.list_service_specific_creds(username)
                                    if isinstance(service_cred_list, str):
                                        print(service_cred_list)
                                    elif service_cred_list:
                                        print("List of service specific creds: ")
                                        for cred in service_cred_list:
                                            print(f"- {cred}")
                                elif creds_choice == "mfa devices":
                                    print("listing mfa devices. ")
                                    mfa_devices_list = users.list_mfa_devices(username)
                                    if isinstance(mfa_devices_list, str):
                                        print(mfa_devices_list)
                                    elif mfa_devices_list:
                                        print("List of MFA Devices: ")
                                        for device in mfa_devices_list:
                                            print(f"- {device}")

# just need to do revoke creds and rotate keys then done

                            elif users_choice == "9":
                                creds_options = ["access key", "certificate", "public ssh key", "service credentials","mfa devices"]
                                creds_options_string = ", ".join(creds_options)
                                credential_choice = input(f"Which type of credentials do you want to revoke? You can choose from the following: {creds_options_string}: ")
                                if credential_choice not in creds_options:
                                    print("Invalid input.")
                                elif credential_choice == "access key":
                                    print("revoking access keys..")
                                    list_of_access_keys = users.list_access_keys(username)
                                    if isinstance(list_of_access_keys, str):
                                        print(list_of_access_keys)
                                    elif list_of_access_keys:
                                        for key in list_of_access_keys:
                                            print(f"Deleting key: {key}")
                                            key_deletion = users.delete_access_key(username=username, access_key_id=key)
                                            print(key_deletion)


                                elif credential_choice == "certificate":
                                    print("revoking certificates")
                                    list_of_certificates = users.list_certificate_ids(username)
                                    if isinstance(list_of_certificates, str):
                                        print(list_of_certificates)
                                    elif list_of_certificates:
                                        for cert in list_of_certificates:
                                            print(f"Deleting certificate: {cert}")
                                            cert_deletion = users.delete_signing_certificate(username=username, cert=cert)
                                            print(cert_deletion)

                                elif credential_choice == "public ssh key":
                                    print("revoking public ssh keys")
                                    list_of_ssh_keys = users.list_public_ssh_keys(username)
                                    if isinstance(list_of_ssh_keys, str):
                                        print(list_of_ssh_keys)
                                    elif list_of_ssh_keys:
                                        for key in list_of_ssh_keys:
                                            print(f"Deleting SSH Keys: {key}")
                                            key_deletion = users.delete_ssh_public_key(username=username, key_id=key)
                                            print(key_deletion)
                                elif credential_choice == "service credentials":
                                    print("Revoking Service Credentials..")
                                    list_of_creds = users.list_service_specific_creds(username)
                                    if isinstance(list_of_creds, str):
                                        print(list_of_creds)
                                    elif list_of_creds:
                                        for cred in list_of_creds:
                                            cred_deletion = users.delete_service_specific_creds(username, cred=cred)
                                            print(cred_deletion)
                                elif credential_choice == "mfa devices":
                                    print("Deactivating MFA devices..")
                                    list_of_mfa = users.list_mfa_devices(username)
                                    if isinstance(list_of_mfa, str):
                                        print(list_of_mfa)
                                    elif list_of_mfa:
                                        for device in list_of_mfa:
                                            device_deactivation = users.deactivate_mfa_device(username, serial_id=device)
                                            print(device_deactivation)


                            elif users_choice == "10":
                                print("Rotating Keys..")
                                # list keys
                                list_of_access_keys = users.list_access_keys(username)
                                if isinstance(list_of_access_keys, str):
                                    print(list_of_access_keys)
                                elif list_of_access_keys:
                                    print("List of keys: ")
                                    length_of_keys = len(list_of_access_keys) + 1
                                    for key in list_of_access_keys:
                                        print(f"- {key}")
                                    key_list_string = ", ".join(list_of_access_keys)
                                    which_key_rotate = int(input(f"Which key would you like to rotate? {key_list_string} \n Choose the corresponding number of the key in the list to rotate it. ")) -1
                                    length_list = [item for item in range(length_of_keys)]
                                    if which_key_rotate not in range(0, len(length_list) -1):
                                        print("Invalid option. ")
                                    else:
                                        # get access key from index
                                        chosen_key = list_of_access_keys[which_key_rotate]
                                        print(f"You have chosen: {chosen_key}.")
                                        revoke = input(f"Do you want to revoke this key? {chosen_key} \n Yes or anything else to exit. ")
                                        if revoke != "yes":
                                            print("Aborting key deletion..")
                                        elif revoke == "yes":
                                            print(f"Revoking {chosen_key}..")
                                            revoke_key = users.delete_access_key(username, access_key_id=chosen_key)
                                            print(revoke_key)
                                    # create new key and expose access key id and secret access
                                            create = input("Do you want to create the new key?: (yes or anything else to exit) ")
                                            if create != "yes":
                                                print("Aborting key creation..")
                                            elif create == "yes":
                                                print("WARNING! Keep these values secure as it is highly privileged information. ")
                                                new_access_key_id, new_secret_access_key = users.create_access_key(
                                                    username)
                                                print(f"Access Key ID: {new_access_key_id[0]}")
                                                print(f"Secret Access Key: {new_secret_access_key[0]}")



                            elif users_choice == "11":
                                print(f"Deleting {username}...\n")
                                iam_user_delete_response = users.delete_iam_user(username)
                                print(iam_user_delete_response)
                                break

                            else:
                                print("Exiting.")
                                break

                elif users_choice == "3":
                    list_of_users = users.list_iam_users()
                    if isinstance(list_of_users, str):
                        print(list_of_users)
                    elif list_of_users:
                        print("List of users in your accounts: ")
                        for user in list_of_users:
                            print(f"-{user}")



                elif users_choice == "4":
                    user_to_delete = input("Enter the name of the user you want to delete: ").lower()
                    users.delete_iam_user(user_to_delete)
        elif choice == "5":
            print("Admin console...")

        elif choice == "q":
            print("Exiting the programme..")
            exit()

if __name__ == "__main__":
    main()





