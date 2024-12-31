import json
import boto3

def create_iam_policy_file(name, sid, effect, service, action, resource):
    policy_dict = {
        "Sid": sid,
        "Effect": effect,
        "Action": [f"{service}:{action}"],
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
        new_file = f"./output_policies/{name}_policy.json"

        # Write the updated policy to the new file
        with open(new_file, mode="w") as new_policy_file:
            json.dump(policy_data, new_policy_file, indent=4)
            print(f"Policy file created: {new_file}")

    return new_file  # Return the new file name


def delete_iam_policy_file():
    pass
    # logic to delete the policy file if there is some kind of error when creating it in AWS so dodgy templates aren't hanging around


def create_policy(new_policy):
    iam_client = boto3.client("iam")
    file_name = new_policy
    policy_name = file_name.split("/")[-1].split(".")[0]
    with open(file_name, mode="r") as policy_file:
        policy_contents = policy_file.read()

    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_contents,  # JSON string of the policy
        )
        print(f"Policy created successfully! ARN: {response['Policy']['Arn']}")
    except iam_client.exceptions.MalformedPolicyDocumentException as e:
        print(f"Malformed policy document: in {policy_name}", e)
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        print(f"Policy called {policy_name} already exists:", e)
    except Exception as e:
        print(f"Error creating policy {policy_name}:", e)



def get_user_input_policy():
    output = []
    name = input("Enter your policy name: ").lower()
    output.append(name)
    sid = input("Give me your SID: ")
    output.append(sid)
    effect = input("Give me your effect (Allow or Deny): ").capitalize()
    output.append(effect)
    service = input("Give me your service (e.g., s3): ")
    output.append(service)
    action = input("Give me your action (e.g., GetObject): ")
    output.append(action)
    resource = input("Give me your resource ARN: ")
    output.append(resource)
    return output


user_inputs = get_user_input_policy()
policy_file_name = create_iam_policy_file(*user_inputs)
create_policy(policy_file_name)