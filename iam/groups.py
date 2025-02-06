from . import iam_client
from iam import iam_policy
from iam import users



def create_iam_group(group_name):
    if group_name == "":
        return "Invalid group name."
    else:
        try:
            iam_client.create_group(GroupName=group_name)
            return f"{group_name} successfully created."
        except iam_client.exceptions.EntityAlreadyExistsException as e:
            return f"{e}"



def list_groups():
    try:
        response = iam_client.list_groups()
        group_name = response.get("Groups", [])
        if not group_name:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Groups found"}},
                operation_name="ListGroups"
            )
        group_names = [group['GroupName'] for group in group_name]
        return group_names
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"


def attach_policy_to_group(policy_arn, group_name):
    list_of_policies = iam_policy.list_policies_in_aws(arn=True,policy_type="All")
    if policy_arn not in list_of_policies:
        return f"Error, policy not found in AWS."
    else:
        list_of_groups = list_groups()
        if group_name not in list_of_groups:
            return f"Error, invalid group."
        else:
            try:
                iam_client. attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
                return f"Succesfully attached {policy_arn} to {group_name}"
            except iam_client.exceptions.PolicyNotAttachableException as e:
                return f"{e}"
            except Exception as e:
                return f"{e}"



def detach_policy_from_group(policy_arn, group_name):
    list_of_policies = iam_policy.list_policies_in_aws(arn=True,policy_type="All")
    if policy_arn not in list_of_policies:
        return f"Error, policy not found in AWS."
    else:
        list_of_groups = list_groups()
        if group_name not in list_of_groups:
            return f"Error, invalid group."
        else:
            try:
                iam_client.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
                return f"Successfully detached {policy_arn} from {group_name}"
            except iam_client.exceptions.NoSuchEntityException as e:
                return f"{e}"
            except Exception as e:
                return f"{e}"

def list_group_policies(group_name, policy_type):
    # get list of groups:
    list_of_groups = list_groups()
    if group_name not in list_of_groups:
        return "Group not found"
    else:
        if policy_type == "All":
            # Get attached (managed) policies
            response = iam_client.list_attached_group_policies(GroupName=group_name)
            managed_policies = response.get("AttachedPolicies", [])
            managed_policy_arns = [policy['PolicyArn'] for policy in managed_policies]

            # Get inline policies
            response = iam_client.list_group_policies(GroupName=group_name)
            inline_policies = response.get("PolicyNames", [])

            # If you prefer a single list with both types:
            combined_policies = managed_policy_arns + inline_policies
            if not combined_policies:
                return "No managed or inline policies attached."
            else:
                return combined_policies

        elif policy_type == "Managed":
            # Get attached (managed) policies
            response = iam_client.list_attached_group_policies(GroupName=group_name)
            managed_policies = response.get("AttachedPolicies", [])
            if not managed_policies:
                return "No policies found."
            else:
                managed_policy_arns = [policy['PolicyArn'] for policy in managed_policies]
                return managed_policy_arns

        elif policy_type == "Inline":
            # Get inline policies
            response = iam_client.list_group_policies(GroupName=group_name)
            inline_policies = response.get("PolicyNames", [])
            if not inline_policies:
                return "No inline policies found."
            else:
                return inline_policies


def list_users_in_group(group_name):
    list_of_groups = list_groups()
    if group_name not in list_of_groups:
        return "Group not found. "
    try:
        response = iam_client.get_group(GroupName=group_name)
        users_in_group = response.get('Users', [])
        if not users_in_group:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Users found"}},
                operation_name="GetGroup"
            )
        usernames = [user['UserName'] for user in users_in_group]
        return usernames
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"



def list_groups():
    try:
        response = iam_client.list_groups()
        group_name = response.get("Groups", [])
        if not group_name:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Groups found"}},
                operation_name="ListGroups"
            )
        group_names = [group['GroupName'] for group in group_name]
        return group_names
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"

def user_to_group(group_name, user, add=True):
    list_of_groups = list_groups()
    if group_name not in list_of_groups:
        return "Group not found. "
    if add:
        list_users = list_users_in_group(group_name)
        if user in list_users:
            return "User already in group."
        else:
            try:
                iam_client.add_user_to_group(GroupName=group_name, UserName=user)
                return f"Added {user} to {group_name}."
            except iam_client.exceptions.NoSuchEntityException as e:
                return {f"{e}"}
    else:
        list_users = list_users_in_group(group_name)
        if user not in list_users:
            return "User isn't in the group."
        else:
            try:
                iam_client.remove_user_from_group(GroupName=group_name, UserName=user)
                return f"Removed {user} from {group_name}."
            except iam_client.exceptions.NoSuchEntityException as e:
                return {f"{e}"}

def delete_inline_policies(group_name):
    policies = list_group_policies(group_name=group_name, policy_type="Inline")
    for policy in policies:
        try:
            iam_client.delete_group_policy(GroupName=group_name, PolicyName=policy)
            return f"Deleted {policy}"
        except Exception as e:
            return f"{e}"



def delete_group(group_name):
    # remove users
    users_in_group = list_users_in_group(group_name)
    if isinstance(users_in_group, str):
        print(users_in_group)
    elif users_in_group:
        for item in users_in_group:
            remove = user_to_group(group_name, item, add=False)
            print(remove)
        # detach policies
    policies = list_group_policies(group_name, policy_type="All")
    for policy in policies:
        detach = detach_policy_from_group(policy_arn=policy, group_name=group_name)
        print(detach)
    # delete inline policies
    delete_inline = delete_inline_policies(group_name)
    # delete group
    try:
        iam_client.delete_group(GroupName=group_name)
        return f"{group_name} deleted."
    except iam_client.exceptions.DeleteConflictException as e:
        return {f"{e}"}
    except Exception as e:
        return f"{e}"