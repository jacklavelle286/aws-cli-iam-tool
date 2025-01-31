from . import iam_client
from . import json
from . import iam_policy


def create_role(role_name, description, assume_role_type_value, assume_role_entity_value, user):
    try:
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        'assume_role_type': 'assume_role_entity'
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        if user is True:
            allowed_options = "AWS"
            if assume_role_type_value not in allowed_options:
                raise ValueError(f"Invalid input for Assume Role Type, must be {allowed_options}")
            if len(assume_role_entity_value) != 12 or not assume_role_entity_value.isdigit():
                raise ValueError("Invalid input for Assume Role Type, must be a valid 12-digit AWS account number.")

        elif user is False:
            allowed_options = "Service"
            if assume_role_type_value not in allowed_options:
                raise ValueError(f"Invalid input for Assume Role Type, must be {allowed_options}")

        principal_dict = assume_role_policy_document['Statement']
        for item in principal_dict:
            to_edit = item["Principal"]
            original_value = to_edit.pop('assume_role_type')
            if user is True:
                to_edit[assume_role_type_value] = f"arn:aws:iam::{assume_role_entity_value}:root"
            elif not user:
                to_edit[assume_role_type_value] = f"{assume_role_entity_value}.amazonaws.com"

        policy = json.dumps(assume_role_policy_document)

        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=policy,
            Description=description
        )

        role = response.get("Role", {})
        role_arn = role.get('Arn', 'No ARN found')
        return f"Role successfully created with ARN: {role_arn}"

    except ValueError as e:
        return f"Error: {e}"  # Return instead of exiting
    except iam_client.exceptions.InvalidInputException as e:
        return f"Invalid Input: {e}"
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        return f"Role already exists: {e}"
    except iam_client.exceptions.MalformedPolicyDocumentException as e:
        return f"Malformed Policy Document: {e} - {policy}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

class NoRolesFoundException(Exception):
    """Exception raised when no Roles are found."""
    pass


def list_roles():
    try:
        response = iam_client.list_roles()
        roles = response.get("Roles", [])
        roles_list = [role['RoleName'] for role in roles]
        if not roles_list:
            raise NoRolesFoundException("No IAM users found in the account.")
        return roles_list

    except iam_client.exceptions.ServiceFailureException as e:
        return e

class InvalidPolicy(Exception):
    pass

def attach_policy_to_role(role_name, policy):
    try:
        list_of_policy_arns = iam_policy.list_policies_in_aws(arn=True, policy_type="All")
        if policy not in list_of_policy_arns:
            raise ValueError(f"Invalid Policy ARN: {policy}.")

        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy)
        return f"Policy {policy} successfully attached to role {role_name}"

    except iam_client.exceptions.PolicyNotAttachableException as e:
        return f"Policy is not attachable: {e}"
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"Error: Role {role_name} does not exist: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

class NoPolicyRolesFoundException(Exception):
    pass


def list_managed_policies_attached_to_role(role_name):
    policy_names = iam_client.list_attached_role_policies(RoleName=role_name)
    if not policy_names:
        raise NoPolicyRolesFoundException("No Roles found in the account.")
    policy = policy_names["AttachedPolicies"]
    policy_arn_list = []
    for item in policy:
        policy_arn = item["PolicyArn"]
        policy_arn_list.append(policy_arn)
    return policy_arn_list



def list_roles():
    try:
        response = iam_client.list_roles()
        roles_in_account = response.get("Roles", [])
        roles_list = [role['RoleName'] for role in roles_in_account]
        return roles_list
    except Exception as e:
        return f"Unable to list roles. {e}"


def detach_policy_from_role(role_name, policy):
    try:
        list_of_policy_arns = iam_policy.list_policies_in_aws(arn=True, policy_type="All")
        if policy not in list_of_policy_arns:
            raise ValueError(f"Invalid Policy ARN: {policy}.")
        iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy)
        return f"Policy {policy} successfully detached from role {role_name}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"