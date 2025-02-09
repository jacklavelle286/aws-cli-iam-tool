from itertools import cycle

from iam import iam_policy, users, roles, groups
from iam import iam_client
import getpass
from simple_term_menu import TerminalMenu

def main():
    main_menu_title = "Welcome to the PYAM CLI Tool"
    main_menu_items = [
        "IAM Policies",
        "IAM Users",
        "Roles",
        "Groups",
        "Admin Panel",
        "Quit"
    ]
    main_menu_exit = False

    main_menu = TerminalMenu(
        menu_entries=main_menu_items,
        title=main_menu_title,
        cycle_cursor=True,
    )

    while not main_menu_exit:
        main_sel = main_menu.show()
        if main_sel == 0:
            policy_menu_title = "IAM Policy Administration"
            policy_menu_items = [
                "Policy Creation",
                "Delete Local Policy Files",
                "Delete Policy Within AWS",
                "Inspect Policy",
                "Return to main menu"
            ]

            policy_menu_exit = False

            policy_menu = TerminalMenu(
                menu_entries=policy_menu_items,
                title=policy_menu_title,
                cycle_cursor=True,
            )
            while not policy_menu_exit:
                policy_menu_sel = policy_menu.show()
                if policy_menu_sel == 0:
                    iam_policy.user_inputs = iam_policy.get_user_input_policy()
                    iam_policy.policy_file_name = iam_policy.create_iam_policy_file(iam_policy.user_inputs)
                    iam_policy.create_policy(iam_policy.policy_file_name)
                elif policy_menu_sel == 1:
                    policy_list = iam_policy.list_local_policy_files()
                    policy_list_menu_items = []
                    for policy in policy_list:
                        policy_list_menu_items.append(policy)

                    policy_list_menu_exit = False
                    if not policy_list:
                        print("No policies found locally. ")
                        policy_list_menu_exit = True

                    policy_list_menu = TerminalMenu(
                        menu_entries=policy_list_menu_items,
                        cycle_cursor=True,
                    )
                    while not policy_list_menu_exit:
                        selected_index = policy_list_menu.show()
                        selected_policy = policy_list_menu_items[selected_index]
                        delete = iam_policy.delete_policy_file(selected_policy)
                        policy_list_menu_exit = True
                elif policy_menu_sel == 2:
                    print("Which policy do you want to delete within AWS?\n")
                    list_of_policies = iam_policy.list_policies_in_aws(arn=False, policy_type="Local")

                    if isinstance(list_of_policies, str):
                        print(list_of_policies)
                        policy_menu_exit = True
                    elif list_of_policies:
                        delete_aws_policy_items = [policy for policy in list_of_policies]
                        delete_aws_policy_exit = False

                        delete_aws_policy_menu = TerminalMenu(
                            menu_entries=delete_aws_policy_items,
                            cycle_cursor=True,
                        )

                        while not delete_aws_policy_exit:
                            selected_index = delete_aws_policy_menu.show()  # Get index of selection
                            if selected_index is None:  # Handle case when user cancels the selection
                                print("No policy selected.")
                                break

                            selected_policy = delete_aws_policy_items[selected_index]  # Get actual policy name

                            # Delete policy
                            delete_response = iam_policy.delete_policy_remotely(selected_policy)
                            print(delete_response)

                            # Ask user if they want to delete another policy
                            confirm_menu = TerminalMenu(["Delete another", "Exit"])
                            confirm_selection = confirm_menu.show()

                            if confirm_selection == 1:  # User chose "Exit"
                                delete_aws_policy_exit = True

                elif policy_menu_sel == 3:
                    print("Inpsecting policy...")
                    inspect_policy = input("Choose a policy to inspect: ")
                    policy_object = iam_policy.describe_policy(inspect_policy)
                    if policy_object is None:
                        print("Error when fetching policy document document. ")
                    elif not policy_object:
                        print("Policy document not found.")
                    else:
                        print(policy_object)

                elif policy_menu_sel == 4:
                    print("Returning to main menu..")
                    policy_menu_exit = True



        elif main_sel == 1:
            user_menu_title = "IAM User Administration"
            user_menu_items = [
                "IAM User Creation",
                "Interact with IAM User",
                "List IAM Users",
                "Delete IAM User",
                "Return to Main Menu"
            ]
            user_menu_exit = False

            user_menu = TerminalMenu(
                menu_entries=user_menu_items,
                title=user_menu_title,
                cycle_cursor=True,
            )

            while not user_menu_exit:
                user_sel = user_menu.show()
                if user_sel == 0:
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

                elif user_sel == 1:
                    print("interacting with iam users..")
                    username = input("Enter the name of the IAM user you'd like to work with: ")
                    print(f"You chose {username}")
                    current_list_of_users = users.list_iam_users()
                    if username not in current_list_of_users:
                        print("Your user does not exist, here is the list of users:")
                        for user in current_list_of_users:
                            print(f"- {user}")
                    else:
                        interact_user_menu_title = "Interaction with an IAM User"
                        interact_user_menu_items = [f"List Policies attached to {username}", f"List Groups {username} is in", f"Add {username} to IAM Groups", f"Remove {username} from a Group", f"Add Policies to {username}", f"Remove Policies from {username}", f"Change Password for {username}", f"List credentials for {username}", f"Revoke credentials for {username}", f"Rotate access keys for {username}", f"Delete {username}", "Return to IAM User Menu"]
                        interact_user_menu_exit = False

                        interact_user = TerminalMenu(
                            menu_entries=interact_user_menu_items,
                            title=interact_user_menu_title,
                            cycle_cursor=True,
                        )
                        while not interact_user_menu_exit:
                            interact_user_sel = interact_user.show()
                            if interact_user_sel == 0:
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


                            elif interact_user_sel == 1:
                                print("listing groups")
                                list_of_groups = users.list_groups_for_user(username)
                                if isinstance(list_of_groups, str):
                                    print(list_of_groups)
                                elif list_of_groups:
                                    print("Groups: ")
                                    for group in list_of_groups:
                                        print(f"-{group}")

                            elif interact_user_sel == 2:
                                print("Adding to group...")



                            elif interact_user_sel == 3:
                                print(f"Removing {username} from groups....")
                                # check groups user is in
                                groups_for_user = users.list_groups_for_user(username)
                                if isinstance(groups_for_user, str):
                                    print(groups_for_user)
                                elif groups_for_user:
                                    for group in groups_for_user:
                                        print(f"Removing {username} from {group}")


                            elif interact_user_sel == 4:
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




                            elif interact_user_sel == 5:
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



                            elif interact_user_sel == 6:
                                print("Changing password")
                                password = getpass.getpass("Enter your password: ")
                                change_password = users.change_password(username, password)
                                print(change_password)

                            elif interact_user_sel == 7:
                                print("listing credentials...")
                                creds_options = [
                                    "access key",
                                    "certificate",
                                    "public ssh key",
                                    "service credentials",
                                    "mfa devices"
                                ]
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
                                        selected_index = listed_attached_policies_menu.show()  # Get index of selection
                                        selected_policy = list_of_policies_attached_to_role[selected_index]  # Get actual value
                                        detach = roles.detach_policy_from_role(role_name=role_name, policy=selected_policy)
                                        print(detach)
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

                            elif interact_user_sel == 8:
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


                            elif interact_user_sel == 9:
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


                            elif interact_user_sel == 10:
                                print(f"Deleting {username}...\n")
                                iam_user_delete_response = users.delete_iam_user(username)
                                interact_user_menu_exit = True
                                if isinstance(iam_user_delete_response, str):  # Error or message response
                                    print(iam_user_delete_response)
                                else:
                                    print("User deleted successfully.")

                            elif interact_user_sel == 11:
                                interact_user_menu_exit = True


                elif user_sel == 2:
                    list_of_users = users.list_iam_users()
                    if isinstance(list_of_users, str):
                        print(list_of_users)
                    elif list_of_users:
                        print("List of users in your accounts: ")
                        for user in list_of_users:
                            print(f"-{user}")


                elif user_sel == 3:
                    user_to_delete = input("Enter the name of the user you want to delete: ").lower()
                    iam_user_delete_response = users.delete_iam_user(user_to_delete)
                    if isinstance(iam_user_delete_response, str):  # Error or message response
                        print(iam_user_delete_response)
                    else:
                        print("User deleted successfully.")


                elif user_sel == 4:
                    user_menu_exit = True

        elif main_sel == 2:
            roles_menu_title = "IAM Role Administration"
            roles_menu_items = [
                "Create Role",
                "List Roles",
                "Attach Policy To Role",
                "Detach Policy From Role",
                "Delete Role",
                "Disable Role",
                "Enable Role",
                "Return to Main Menu"
            ]
            role_menu_exit = False
            role_menu = TerminalMenu(
                menu_entries=roles_menu_items,
                title=roles_menu_title,
                cycle_cursor=True,
            )
            while not role_menu_exit:
                role_sel = role_menu.show()
                if role_sel == 0:
                    name = input("Enter your role name: ")
                    description = input("Enter the role's description: ")
                    print("What type of role would you like to create? ")
                    role_type_items = [
                        "Role for IAM User",
                        "Role For AWS Service",
                    ]
                    role_type_exit = False
                    role_type = TerminalMenu(
                        menu_entries=role_type_items,
                        cycle_cursor=True,
                    )
                    while not role_type_exit:
                        role_type_sel = role_type.show()
                        if role_type_sel == 0:
                            account_number = input("Enter an AWS Account number:  ")
                            role_creation = roles.create_role(user=True, role_name=name, description=description, assume_role_type_value="AWS", assume_role_entity_value=account_number)
                            print(role_creation)
                            role_type_exit = True
                        elif role_type_sel == 1:
                            # role for aws service
                            aws_service = input("What service would you like this role to assume? for example ec2, iam: ")
                            role_creation = roles.create_role(user=False, role_name=name, description=description, assume_role_type_value="Service", assume_role_entity_value=aws_service)
                            print(role_creation)
                            role_type_exit = True

                elif role_sel == 1:
                    print("Listing roles..")
                    list_of_roles = roles.list_roles()
                    if isinstance(list_of_roles, str):
                        print(list_of_roles)
                    elif list_of_roles:
                        for role in list_of_roles:
                            print(f"-{role}")
                elif role_sel == 2:
                    print("Listing roles..")
                    list_of_roles = roles.list_roles()
                    if isinstance(list_of_roles, str):
                        print(list_of_roles)
                    elif list_of_roles:
                        for role in list_of_roles:
                            print(f"-{role}")
                    role_name = input("Choose your role name: ")
                    if role_name not in list_of_roles:
                        print("Role not valid.")
                    else:
                        policy_arn = input("Choose your policy arn: ")
                        attach = roles.attach_policy_to_role(role_name=role_name, policy=policy_arn)
                        print(attach)

                elif role_sel == 3:
                    list_of_roles = roles.list_roles()
                    if isinstance(list_of_roles, str):
                        print(list_of_roles)
                    elif list_of_roles:
                        print("Here is a list of roles in your account: ")
                        for role in list_of_roles:
                            print(f"- {role}")

                    role_name = input("Choose your role name: ")
                    if role_name not in list_of_roles:
                        print("Role not valid.")
                    else:
                        list_of_policies_attached_to_role = roles.list_managed_policies_attached_to_role(role_name)
                        if not list_of_policies_attached_to_role:
                            print("No policies attached to this role.")
                        else:
                            listed_attached_policies_menu = TerminalMenu(
                                menu_entries=list_of_policies_attached_to_role,
                                cycle_cursor=True,
                            )
                            selected_index = listed_attached_policies_menu.show()  # Get index of selection
                            selected_policy = list_of_policies_attached_to_role[selected_index]  # Get actual value
                            detach = roles.detach_policy_from_role(role_name=role_name, policy=selected_policy)
                            print(detach)
                elif role_sel == 4:
                    list_of_roles = roles.list_roles()
                    role_name_to_delete = input("Enter your role name to delete: ")
                    if role_name_to_delete not in list_of_roles:
                        print(f"{role_name_to_delete} not found.")
                    else:
                        print("Detaching policies..")
                        list_detach_policies = roles.list_managed_policies_attached_to_role(role_name=role_name_to_delete)
                        if isinstance(list_detach_policies, str):
                            print(list_detach_policies)
                        elif list_detach_policies:
                            for policy in list_detach_policies:
                                detach = roles.detach_policy_from_role(role_name_to_delete, policy)
                                print(detach)
                        print("Deleting inline roles...")
                        list_inline_policies = roles.list_inline_role_policies(role_name_to_delete)
                        if isinstance(list_inline_policies, str):
                            print(list_inline_policies)
                        elif list_inline_policies:
                            for policy in list_inline_policies:
                                delete = roles.delete_inline_policy_role(role_name_to_delete, policy)
                                print(delete)
                        print("Removing role from instance profile..")
                        delete_instance_profile = roles.remove_role_from_instance_profile(role_name_to_delete)
                        print(delete_instance_profile)
                        print("Deleting role..")
                        delete = roles.delete_role(role_name_to_delete)
                        print(delete)


                elif role_sel == 5:
                    role_list = roles.list_roles()
                    role_name = input("Enter a role to disable: ")
                    if role_name not in role_list:
                        print(f"Role {role_name} Not Found.")
                    else:
                        disable = roles.disable_role(role_name)
                        print(disable)

                elif role_sel == 6:
                    role_list = roles.list_roles()
                    role_name = input("Enter a role to enable: ")
                    if role_name not in role_list:
                        print(f"Role {role_name} Not Found.")
                    else:
                        enable = roles.enable_role(role_name)
                        print(enable)



                elif role_sel == 7:
                    role_menu_exit = True


        elif main_sel == 3:
            groups_menu_title = "IAM Group Administration"
            groups_menu_items = [
                f"Create Group",
                "List Groups",
                "Attach Policy To Group",
                "Detach Policy From Group",
                "List Policies Attached to Group",
                "List Users in Group",
                "Add User To Group",
                "Remove User from Group",
                "Delete Group",
                "Return to Main Menu"
            ]
            groups_menu_exit = False
            groups_menu = TerminalMenu(
                menu_entries=groups_menu_items,
                title=groups_menu_title,
                cycle_cursor=True,
            )
            while not groups_menu_exit:
                group_sel = groups_menu.show()
                if group_sel == 0:
                    group_name = input("Enter your group name. ")
                    new_group = groups.create_iam_group(group_name)
                    print(new_group)
                elif group_sel == 1:
                    list_of_groups = groups.list_groups()
                    if isinstance(list_of_groups, str):
                        print(list_of_groups)
                    elif list_of_groups:
                        print("List of Groups:")
                        for group in list_of_groups:
                            print(f"- {group}")
                elif group_sel == 2:
                    group = input("Choose a group: ")
                    policy = input("Choose a policy arn: ")
                    attach_attempt = groups.attach_policy_to_group(policy_arn=policy, group_name=group)
                    print(attach_attempt)
                elif group_sel == 3:
                    group_name = input("Choose a group: ")
                    policy_arn = input("Choose a policy arn: ")
                    detach = groups.detach_policy_from_group(policy_arn, group_name)
                    print(detach)
                elif group_sel == 4:
                    group_name = input("Choose a group: ")
                    list_of_policies = groups.list_group_policies(group_name=group_name, policy_type="All")
                    if isinstance(list_of_policies, str):
                        print(list_of_policies)
                    elif list_of_policies:
                        for policy in list_of_policies:
                            print(f"-{policy}")
                elif group_sel == 5:
                    group_name = input("Choose a group name: ")
                    list_users_in_group = groups.list_users_in_group(group_name=group_name)
                    if not list_users_in_group:
                        print(list_users_in_group)
                    elif isinstance(list_users_in_group, str):
                        print(list_users_in_group)
                    elif list_users_in_group:
                        for user in list_users_in_group:
                            print(f"-{user}")
                elif group_sel == 6:
                    group = input("Choose a group name: ")
                    user = input("Choose a user: ")
                    add = groups.user_to_group(group, user)
                    print(add)
                elif group_sel == 7:
                    group = input("Choose a group name: ")
                    user = input("Choose a user: ")
                    remove = groups.user_to_group(group, user, add=False)
                    print(remove)
                elif group_sel == 8:
                    delete = input("Choose a group to Delete: ")
                    delete_try = groups.delete_group(delete)
                    print(delete_try)
                elif group_sel == 9:
                    print("Returning to Main Menu...")
                    groups_menu_exit = True


        elif main_sel == 4:
            admin_menu_items = [
                "View Account Summary",
                "Enable/Disable MFA on Root Account",
                "List All Users and Roles",
                "List All Policies and Their Usage",
                "Audit IAM Configuration",
                "Generate IAM Report",
                "Export Configuration for Backup",
                "Return to Main Menu"
            ]

            admin_menu = TerminalMenu(
                menu_entries=admin_menu_items,
                title="Admin Console",
                cycle_cursor=True,
            )

            admin_menu_exit = False
            while not admin_menu_exit:
                admin_sel = admin_menu.show()
                if admin_sel == 0:
                    print("View Account Summary")
                elif admin_sel == 1:
                    print("Enable/Disable MFA on Root Account")
                elif admin_sel == 2:
                    print("List All Users and Roles")
                elif admin_sel == 3:
                    print("List All Policies and Their Usage")
                elif admin_sel == 4:
                    print("Audit IAM Configuration")
                elif admin_sel == 5:
                    print("Generate IAM Report")
                elif admin_sel == 6:
                    print("Export Configuration for Backup")
                elif admin_sel == 7:
                    print("Returning to Main Menu...")
                    admin_menu_exit = True


        elif main_sel == 5:
            print("Exiting the programme..")
            main_menu_exit = True
            exit()

if __name__ == "__main__":
    main()





