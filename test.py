import json
from iam import iam_client



def create_role(role_name, description, assume_role_type_value, assume_role_entity_value, user):
    assume_role_policy_document = {
        'Version': '2012-10-17',
        'Statement': {
            'Effect': 'Allow',
            'Principal': {
                'assume_role_type': 'assume_role_entity'
            },
            'Action': 'sts:AssumeRole'
        }
    }

    if user is True:
        allowed_options = "Account"
        if assume_role_type_value not in allowed_options:
            raise iam_client.exceptions.InvalidInputException(
                error_response={"Error": {"Code": "InvalidInputException",
                                          "Message": f"Invalid input for Assume Role Type, but be {allowed_options}"}},
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
        if assume_role_type_value not in allowed_options :
            raise iam_client.exceptions.InvalidInputException(
                error_response={"Error": {"Code": "InvalidInputException", "Message": f"Invalid input for Assume Role Type, but be {allowed_options}"}},
                operation_name="CreateRole"
            )

    principal_dict = assume_role_policy_document['Statement']['Principal']
    assume_role_type_value = assume_role_type_value
    assume_role_entity_value = assume_role_entity_value
    original_value = principal_dict.pop('assume_role_type')
    principal_dict[assume_role_type_value] = f"{assume_role_entity_value}.amazonaws.com"

    try:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
            Description=description
        )
        role = response.get("Role", {})
        role_arn = role.get('Arn', 'No ARN found')
        return f"Role successfully created with ARN: {role_arn}"
    except iam_client.exceptions.InvalidInputException as e:
        return f"Invalid Input: {e}"
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        return f"{e}"


create_role_output = create_role(role_name="Testeing", description="testing", assume_role_type_value="Account",assume_role_entity_value="123456789011", user=True)
print(create_role_output)


