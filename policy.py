import json
import boto3


name = input("Enter your policy name: ")
sid = input("Give me your SID: ")
effect = input("Give me your effect: ").capitalize()
service = input("Give me your service: ")
action = input("Give me your action: ")
resource = input("Give me your resource ARN: ")

policy_dict = {
    "Sid": sid,
    "Effect": effect,
    "Action": [f"{service}:{action}"],
    "Resource": [resource]
}


with open("policy_template.json", mode="r+") as policy_file:
    policy_data = json.load(policy_file)
    for statement in policy_data.get("Statement", []):
        if "Sid" in statement:
            statement["Sid"] = policy_dict["Sid"]
        if "Effect" in statement:
            statement["Effect"] = policy_dict["Effect"]
        if "Action" in statement:
            statement["Action"] = policy_dict["Action"]
        if "Resource" in statement:
            statement["Resource"] = policy_dict["Resource"]

    new_file = "policy.json"
    with open(new_file, mode="w") as new_policy_file:
        json.dump(policy_data, new_policy_file, indent=4)

    print("Your file has been created: ")


