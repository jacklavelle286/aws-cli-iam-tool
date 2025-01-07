import json
import boto3
import os

#1. add support for multiple blocks within a statement i.e.
# ask - do you want to have another block? and y / n creates a new block within the policy
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
        "Sid": input_data["sid"],
        "Effect": input_data["effect"],
        "Action": action_field,
        "Resource": [input_data["resource"]]
    }

    with open("./templates/policy_template.json", mode="r") as policy_file:
        policy_data = json.load(policy_file)

    for statement in policy_data.get("Statement", []):
        statement.update(policy_dict)

    new_file = f"./output_policies/{input_data['name']}.json"
    with open(new_file, mode="w") as new_policy_file:
        json.dump(policy_data, new_policy_file, indent=4)
        print(f"Policy file created: {new_file}. \n Creating policy in AWS...")

    return new_file


# IAM Policy Creation Functionality
def create_policy(new_policy):
    """
    Create an IAM policy in AWS using the generated JSON policy file.
    """
    iam_client = boto3.client("iam")
    policy_name = os.path.basename(new_policy).split(".")[0]

    with open(new_policy, mode="r") as policy_file:
        policy_contents = policy_file.read()

    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_contents
        )
        arn = response["Policy"]["Arn"]
        print(f"Policy created successfully!: {arn}")
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"Policy called '{policy_name}' already exists in AWS.")
        handle_existing_policy(policy_name, new_policy)
    except iam_client.exceptions.MalformedPolicyDocumentException as e:
        print(f"Malformed policy document for '{policy_name}': {e}")
        delete_policy_file(new_policy=new_policy)
    except Exception as e:
        print(f"Error creating policy '{policy_name}': {e}")
        delete_policy_file(new_policy=new_policy)


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
    iam_client = boto3.client("iam")
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
    iam_client = boto3.client("iam")
    policy_arn = get_iam_policy_arn(new_policy)

    if not policy_arn:
        print("Policy ARN not found.")
        return

    # Get all entities attached to the policy
    response = iam_client.list_entities_for_policy(PolicyArn=policy_arn)
    detach_entities(response, policy_arn)

    # Delete the policy after detachment
    try:
        iam_client.delete_policy(PolicyArn=policy_arn)
        print(f"Policy '{new_policy}' deleted successfully.")
    except iam_client.exceptions.DeleteConflictException as e:
        print(f"Cannot delete policy '{new_policy}' due to remaining attachments: {e}")
    except Exception as e:
        print(f"An error occurred while deleting the policy '{new_policy}': {e}")


def detach_entities(response, policy_arn):
    """
    Detach IAM policy from users, groups, and roles.
    """
    iam_client = boto3.client("iam")

    # Detach from users
    for user in response.get("PolicyUsers", []):
        iam_client.detach_user_policy(UserName=user["UserName"], PolicyArn=policy_arn)
        print(f"Detached policy from user: {user['UserName']}")

    # Detach from roles
    for role in response.get("PolicyRoles", []):
        iam_client.detach_role_policy(RoleName=role["RoleName"], PolicyArn=policy_arn)
        print(f"Detached policy from role: {role['RoleName']}")

    # Detach from groups
    for group in response.get("PolicyGroups", []):
        iam_client.detach_group_policy(GroupName=group["GroupName"], PolicyArn=policy_arn)
        print(f"Detached policy from group: {group['GroupName']}")


def delete_policy_file(new_policy):
    """
    Delete a policy JSON file locally.
    """
    os.remove(new_policy)
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
        policy_path = os.path.join(policies_directory, policy)
        os.remove(policy_path)
    print("Removed all policies locally.")


# Main Program Execution
if __name__ == "__main__":
    user_inputs = get_user_input_policy()
    policy_file_name = create_iam_policy_file(user_inputs)
    create_policy(policy_file_name)
