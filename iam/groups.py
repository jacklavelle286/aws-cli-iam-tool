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


def attach_policy_to_group(policy_arn):
    list_of_policies = iam_policy.list_policies_in_aws(arn=True,policy_type="All")
    if policy_arn not in list_of_policies:
        return f"Error, policy not found in AWS."
    else:
        return f"You selected {policy_arn}"