import json
import boto3
import os

# create iam policy functionality
"""this is the section for creating the iam user"""

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
                delete_policy_remotely(policy_name)

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
        delete_policy_file(new_policy)
    except Exception as e:
        print(f"Error creating policy '{policy_name}': {e}")
        delete_policy_file(new_policy)




    except Exception as e:
        print(f"Error creating policy {policy_name}:", e)
        delete_policy_file(new_policy=new_policy)

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


def get_user_input_policy():
    while True:
        output = []
        name = input("Enter your policy name: ").lower()
        output.append(name)
        sid = input("Give me your SID: ")
        output.append(sid)
        while True:
            effect = input("Give me your effect (Allow or Deny): ").capitalize()
            if effect != "Allow" and effect != "Deny":
                print("Only Allow or Deny will work here, try again. ")
            else:
                break
        output.append(effect)
        service = input("Give me your service (e.g., s3): ")
        output.append(service)

        # Handle wildcard service
        if service == "*":
            resource = input("Give me your resource ARN: ")
            output.append(resource)
            break
        else:
            action = input("Give me your action (e.g., GetObject): ")
            output.append(action)
            resource = input("Give me your resource ARN: ")
            output.append(resource)

        # Add the resource


    print(output)
    return output

# adding functionality to delete iam policy in aws if duplicate or if other reason

def delete_policy_remotely():
    pass

user_inputs = get_user_input_policy()
policy_file_name = create_iam_policy_file(*user_inputs)
create_policy(policy_file_name)