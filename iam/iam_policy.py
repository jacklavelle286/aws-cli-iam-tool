from . import iam_client
from . import os
from . import json
from . import subprocess
from iam import users
from iam import groups
from . import TerminalMenu


# User Input Functionality
def get_user_input_policy():
    """
    Collect user input for policy details, handling wildcards for service and actions.
    Returns a dictionary with all input data.
    """
    input_data = {
        "name": input("Enter your policy name: ").strip().lower(),
        "sid": input("Give me your SID: ").strip(),
        "effect": input("Give me your effect (Allow or Deny): ").strip().capitalize(),
        # update here so that the user is directed to the menu instead
        "service": input("Give me your service (e.g., s3 or * for all services): ").strip().lower(),
        "action": input("Give me your action (e.g., GetObject or * for all actions): ").strip(),
        "resource": input("Give me your resource ARN (e.g., arn:aws:s3:::bucket-name): ").strip()
    }

    # Handle wildcard service or action
    if input_data["service"] == "*":
        print("Wildcard for service detected. This policy will apply to all services.")
        input_data["action"] = "*"
    elif input_data["action"] == "*":
        print("Wildcard for action detected. This policy will apply to all actions for the specified service.")
    return input_data


# IAM Policy File Creation Functionality
def create_iam_policy_file(input_data):
    """
    Create a JSON policy file based on user input and save it to the output_policies directory.
    """
    action_field = ["*"] if input_data["service"] == "*" or input_data["action"] == "*" else [
        f"{input_data['service']}:{input_data['action']}"]

    policy_dict = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": input_data["sid"],
                "Effect": input_data["effect"],
                "Action": action_field,
                "Resource": [input_data["resource"]]
            }
        ]
    }

    # Ask user if they want to add more statement blocks
    add_more = input("Do you want to add another statement block? (yes/no): ").strip().lower()
    while add_more == "yes":
        sid = input("Give me another SID: ").strip()

        effect = allow_or_deny_option
        service = input("Give me the service (e.g., s3): ").strip().lower()
        action = input("Give me the action (e.g., GetObject): ").strip()
        resource = input("Give me the resource ARN: ").strip()

        action_field = ["*"] if service == "*" or action == "*" else [f"{service}:{action}"]

        new_block = {
            "Sid": sid,
            "Effect": effect,
            "Action": action_field,
            "Resource": [resource]
        }
        policy_dict["Statement"].append(new_block)
        add_more = input("Do you want to add another statement block? (yes/no): ").strip().lower()

    # Save the full policy to a file
    new_file = f"./output_policies/{input_data['name']}.json"
    with open(new_file, mode="w") as new_policy_file:
        json.dump(policy_dict, new_policy_file, indent=4)
        print(f"Policy file created: {new_file}. \n Creating policy in AWS...")

    return new_file

def describe_policy(policy_name):

    policy_list=list_policies_in_aws(policy_type="All", arn=False)
    if policy_name not in policy_list:
        print("Policy doesn't exist in AWS. Exiting...")
        return None


    policy_arn = get_iam_policy_arn(policy_name)
    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version_id = policy['Policy']['DefaultVersionId']
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy_version_id
        )

        compact_json = json.dumps(policy_version['PolicyVersion']['Document'])
        result = subprocess.run(
            ["jq", "."],
            input=compact_json,
            text=True,
            capture_output=True,
            check=True
        )

        return result.stdout

    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity exception: {e}.")
        return None
    except iam_client.exceptions.InvalidInputException as e:
        print(f"Invalid input exception: {e}.")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failuure: {e}.")
        return None



# IAM Policy Creation Functionality
def create_policy(policy_file_name):
    try:
        with open(policy_file_name, 'r') as policy_file:
            policy_document = policy_file.read()
        response = iam_client.create_policy(
            PolicyName=os.path.basename(policy_file_name).split(".")[0],
            PolicyDocument=policy_document
        )
        print(f"Policy created successfully!: {response['Policy']['Arn']}")
        return response['Policy']['Arn']
    except Exception as e:
        print(f"Error creating policy: {e}")
        return None



# Helper Functions for IAM Policy Management
def handle_existing_policy(policy_name, new_policy):
    """
    Handle cases where a policy with the same name already exists in AWS.
    """
    delete_choice = input(f"Policy '{policy_name}' exists. Delete and recreate? (yes/no): ").strip().lower()
    if delete_choice == "yes":
        confirm_delete = input(f"Type the name of the policy to confirm deletion: {policy_name}: ").strip().lower()
        if confirm_delete == policy_name.lower():
            delete_policy_remotely(new_policy)
            create_policy(new_policy)
        else:
            print("Policy deletion aborted.")
    else:
        print("Policy creation aborted.")


def get_iam_policy_arn(new_policy):
    """
    Get the ARN of an existing policy by name.
    """

    policy_name = os.path.basename(new_policy).split(".")[0]
    paginator = iam_client.get_paginator('list_policies')
    for page in paginator.paginate(Scope="All"):
        for policy in page['Policies']:
            if policy['PolicyName'] == policy_name:
                return policy['Arn']
    return None

def delete_policy_remotely(new_policy):
    """
    Delete an existing IAM policy remotely, detaching it from all entities.
    """

    policy_arn = get_iam_policy_arn(new_policy)

    if not policy_arn:
        print("Policy ARN not found.")
        return

    # Get all entities attached to the policy
    response = iam_client.list_entities_for_policy(PolicyArn=policy_arn)
    detach_entities(response, policy_arn, attach_type="users")
    detach_entities(response, policy_arn, attach_type="groups")
    detach_entities(response, policy_arn, attach_type="roles")

    # Delete the policy after detachment
    try:
        iam_client.delete_policy(PolicyArn=policy_arn)
        print(f"Policy '{new_policy}' deleted successfully.")
    except iam_client.exceptions.DeleteConflictException as e:
        print(f"Cannot delete policy '{new_policy}' due to remaining attachments: {e}")
    except Exception as e:
        print(f"An error occurred while deleting the policy '{new_policy}': {e}")


def detach_policy(username, target_type, policy_arn):
    if target_type == "user".lower():
        user_detach = iam_client.detach_user_policy(UserName=username, PolicyArn=policy_arn)
        return user_detach
    elif target_type == "group".lower():
        group_detach = iam_client.detach_group_policy(UserName=username, PolicyArn=policy_arn)
        return group_detach
    elif target_type == "role".lower():
        role_detach = iam_client.detach_role_policy(UserName=username, PolicyArn=policy_arn)
        return role_detach


def detach_entities(response, policy_arn, attach_type):

    if attach_type == "users":
        # Detach from users
        for user in response.get("PolicyUsers", []):
            iam_client.detach_user_policy(UserName=user["UserName"], PolicyArn=policy_arn)
            print(f"Detached policy from user: {user['UserName']}")

    elif attach_type == "roles":
        # Detach from roles
        for role in response.get("PolicyRoles", []):
            iam_client.detach_role_policy(RoleName=role["RoleName"], PolicyArn=policy_arn)
            print(f"Detached policy from role: {role['RoleName']}")

    elif attach_type == "groups":
        # Detach from groups
        for group in response.get("PolicyGroups", []):
            iam_client.detach_group_policy(GroupName=group["GroupName"], PolicyArn=policy_arn)
            print(f"Detached policy from group: {group['GroupName']}")
    else:
        return "invalid option. "


def delete_policy_file(new_policy):
    """
    Delete a policy JSON file locally.
    """
    os.remove(f"output_policies/{new_policy}")
    print(f"policy successfully locally deleted: {new_policy}")


def delete_all_policies_locally():
    """
    Delete all policy JSON files in the output_policies directory.
    """
    policies_directory = "./output_policies"
    if not os.path.exists(policies_directory):
        print("No policies to delete locally.")
        return

    policies = os.listdir(policies_directory)
    for policy in policies:
        print(f"Removing policy: {policy}")
        policy_path = os.path.join(policies_directory, policy)
        os.remove(policy_path)
    print("Removed all policies locally.")


def list_local_policy_files():
    policies_directory = "./output_policies"
    policies_list = os.listdir(policies_directory)
    return policies_list



def list_policies_in_aws(arn, policy_type):
    """
    List policies in AWS.
    """
    all_policies = []
    if policy_type not in ['All', 'AWS', 'Local']:
        print("Invalid policy type input.")
        return None
    else:
        paginator = iam_client.get_paginator('list_policies')
        for page in paginator.paginate(Scope=policy_type, OnlyAttached=False, PolicyUsageFilter='PermissionsPolicy'):
            all_policies.extend(page.get("Policies", []))
        if arn:
            return [policy['Arn'] for policy in all_policies]
        else:
            return [policy['PolicyName'] for policy in all_policies]

