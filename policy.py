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
    with open("policy_template.json", mode="r+") as policy_file:
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
        new_file = f"{name}_policy.json"

        # Write the updated policy to the new file
        with open(new_file, mode="w") as new_policy_file:
            json.dump(policy_data, new_policy_file, indent=4)
            print(f"Policy file created: {new_file}")

    return new_file  # Return the new file name


def create_policy(new_policy, path="/"):
    iam_client = boto3.client("iam")
    file_name = new_policy
    with open(file_name, mode="r") as policy_file:
        policy_contents = policy_file.read()

    try:
        response = iam_client.create_policy(
            PolicyName=file_name.split(".")[0],  # Use file name without extension
            PolicyDocument=policy_contents,  # JSON string of the policy
            Path=path  # Optional path parameter
        )
        print(f"Policy created successfully! ARN: {response['Policy']['Arn']}")
    except iam_client.exceptions.MalformedPolicyDocumentException as e:
        print("Malformed policy document:", e)
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        print("Policy already exists:", e)
    except Exception as e:
        print("Error creating policy:", e)


# Main script
name = input("Enter your policy name: ")
sid = input("Give me your SID: ")
effect = input("Give me your effect (Allow or Deny): ").capitalize()
service = input("Give me your service (e.g., s3): ")
action = input("Give me your action (e.g., GetObject): ")
resource = input("Give me your resource ARN: ")

# Create the policy file dynamically named
policy_file_name = create_iam_policy_file(name=name, sid=sid, effect=effect, service=service, action=action, resource=resource)

# Use the dynamically named file to create the policy
create_policy(policy_file_name)
