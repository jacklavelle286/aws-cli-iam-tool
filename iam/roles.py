from . import iam_client
from . import json


def create_role(role_name, description, assume_role_type_value, assume_role_entity_value, user):
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
            raise iam_client.exceptions.InvalidInputException(
                error_response={"Error": {"Code": "InvalidInputException",
                                          "Message": f"Invalid input for Assume Role Type, must be {allowed_options}"}},
                operation_name="CreateRole"
            )
        if len(assume_role_entity_value) != 12:
            raise iam_client.exceptions.InvalidInputException(
                error_response={"Error": {"Code": "InvalidInputException",
                                          "Message": f"Invalid input for Assume Role Type, but be vali 12 digit AWS account number."}},
                operation_name="CreateRole"
            )

    elif user is False:

        allowed_options = "Service"
        if assume_role_type_value not in allowed_options:
            raise iam_client.exceptions.InvalidInputException(
                error_response={"Error": {"Code": "InvalidInputException",
                                          "Message": f"Invalid input for Assume Role Type, but be {allowed_options}"}},
                operation_name="CreateRole"
            )

    principal_dict = assume_role_policy_document['Statement']
    for item in principal_dict:
        to_edit = item["Principal"]
        original_value = to_edit.pop('assume_role_type')
        if user is True:
            to_edit[assume_role_type_value] = f"arn:aws:iam::{assume_role_entity_value}:root"
        elif not user:
            to_edit[assume_role_type_value] = f"{assume_role_entity_value}.amazonaws.com"
        policy = json.dumps(assume_role_policy_document)

    try:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=policy,
            Description=description
        )

        role = response.get("Role", {})
        role_arn = role.get('Arn', 'No ARN found')
        return f"Role successfully created with ARN: {role_arn}"
    except iam_client.exceptions.InvalidInputException as e:
        return f"Invalid Input: {e}"
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        return f"{e}"
    except iam_client.exceptions.MalformedPolicyDocumentException as e:
        return f"{e} - {policy}"