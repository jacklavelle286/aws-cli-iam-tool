import json
import boto3
import os

# User input functionality
def get_user_input_policy():
    output = []
    name = input("Enter your policy name: ").strip().lower()
    output.append(name)
    sid = input("Give me your SID: ").strip()
    output.append({"sid": sid})
    effect = input("Give me your effect (Allow or Deny): ").strip().capitalize()
    output.append({"effect": effect})
    service = input("Give me your service (e.g., s3): ").strip().lower()
    output.append({"service": service})
    action = input("Give me your action (e.g., GetObject): ").strip()
    output.append({"action": action})
    resource = input("Give me your resource ARN: ").strip()
    output.append({"resource": resource})
    return output

# IAM policy file creation functionality
def create_iam_policy_file(name, sid, effect, service, resource, action=None):
    action_field = ["*"] if service == "*" else [f"{service}:{action}"]
    policy_dict = {
        "Sid": sid,
        "Effect": effect,
        "Action": action_field,
        "Resource": [resource]
    }

    # Open the template file
    with open("./templates/policy_template.json", mode="r+") as policy_file:
        policy_data = json.load(policy_file)

        # Update the policy data
        for statement in policy_data.get("Statement", []):
            if "Sid" in statement:
                statement["Sid"] = policy_dict["Sid"]
            if "Effect" in statement:
                statement["Effect"] = policy_dict["Effect"]
            if "Action" in statement:
                statement["Action"] = policy_dict["Action"]
            if "Resource" in statement:
                statement["Resource"] = policy_dict["Resource"]

        # Dynamically name the new policy file using the `name` argument
        new_file = f"./output_policies/{name}.json"

        # Write the updated policy to the new file
        with open(new_file, mode="w") as new_policy_file:
            json.dump(policy_data, new_policy_file, indent=4)
            print(f"Policy file created: {new_file}. \n Creating policy in AWS...")

    return new_file  # Return the new file name

# IAM policy creation functionality
def create_policy(new_policy):
    iam_client = boto3.client("iam")
    file_name = new_policy
    policy_name = file_name.split("/")[-1].split(".")[0]
    with open(file_name, mode="r") as policy_file:
        policy_contents = policy_file.read()

    try:
        # Attempt to create the policy
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_contents,  # JSON string of the policy
        )
        arn = response["Policy"]["Arn"]
        print(f"Policy created successfully!: {arn}")
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"Policy called '{policy_name}' already exists in AWS.")

        # Ask user if they want to delete the existing policy
        delete_choice = input(
            "Would you like to delete the existing policy and recreate it? (yes/no): "
        ).strip().lower()

        if delete_choice == "yes":
            # Confirm deletion
            confirm_delete = input(
                f"Type the name of the policy to confirm deletion: {policy_name}: "
            ).strip().lower()

            if confirm_delete == policy_name.lower():
                print(f"Deleting policy '{policy_name}'...")
                iam_policy = get_iam_policy_arn(new_policy=new_policy)
                delete_policy_remotely(new_policy=iam_policy)

                # Retry creating the policy
                try:
                    response = iam_client.create_policy(
                        PolicyName=policy_name,
                        PolicyDocument=policy_contents,
                    )

                    arn = response["Policy"]["Arn"]
                    print(f"Policy recreated successfully!: {arn}")
                except Exception as retry_exception:
                    print(
                        f"Error occurred while recreating the policy '{policy_name}': {retry_exception}"
                    )
            else:
                print("Policy deletion aborted. Exiting...")
                exit()
        else:
            print("Policy creation aborted. Exiting...")
            exit()

    except iam_client.exceptions.MalformedPolicyDocumentException as e:
        print(f"Malformed policy document for '{policy_name}': {e}")
        #delete_policy_file(new_policy)
    except Exception as e:
        print(f"Error creating policy {policy_name}:", e)
        delete_policy_file(new_policy=new_policy)

# Helper functions for IAM policy management

def get_iam_policy_arn(new_policy):
    iam_client = boto3.client("iam")
    policy_name = new_policy.split("/")[-1].split(".")[0]
    paginator = iam_client.get_paginator('list_policies')
    for page in paginator.paginate(Scope="All"):
        for policy in page['Policies']:
            if policy['PolicyName'] == policy_name:
                return policy['Arn']

def delete_policy_file(new_policy):
    os.remove(new_policy)
    print(f"policy successfully locally deleted: {new_policy}")

def delete_policy_remotely(new_policy):
    iam_client = boto3.client("iam")
    policy_arn = get_iam_policy_arn(new_policy)
    response = iam_client.list_entities_for_policy(
        PolicyArn=policy_arn
    )

    entities = [list_attached_entities("Users", response), list_attached_entities("Roles", response),
                list_attached_entities("Groups", response)]

    print(f"The policy has the following attachments: \n Users: {entities[0]}  \n Roles: {entities[1]} \n Groups: {entities[2]}")

    confirm_delete = input("Do you want to detach all entities from this policy and confirm deletion? (yes or no) ").lower()
    if confirm_delete != "yes" and confirm_delete != "no":
        print("invalid option, try again. ")
    elif confirm_delete == "no":
        print("Exiting deletion process...")
        exit()
    elif confirm_delete == "yes":
        # detach all entities
        delete_attached_entities(entities, policy_arn)
        # confirm result
        print("Deletion confirmed.. ")
        exit()
    else: print("Error, exiting programme. ")

def list_attached_entities(entity_type, response): # entity type is either Users, Groups or Roles
    entities_list = []
    entities = response[f'Policy{entity_type}']
    entity_type_singular = entity_type[:-1]
    entity_names = [item[f'{entity_type_singular}Name'] for item in entities]
    for entity in entity_names:
        entities_list.append(entity)
    return entities_list

def delete_attached_entities(entities, policy_arn):
    iam_client = boto3.client("iam")
    all_entities = [item for sublist in entities for item in sublist]
    print(all_entities)
    for item in all_entities:
        print(item)
    # DetachUserPolicy, DetachGroupPolicy, or DetachRolePolicy depending on what is passed in!

# Main program
user_inputs = get_user_input_policy()
policy_file_name = create_iam_policy_file(*user_inputs)
create_policy(policy_file_name)
