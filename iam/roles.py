from . import iam_client
from . import json

def create_role(role_name, description, assume_role_type_value, assume_role_entity_value):
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
    principal_dict = assume_role_policy_document['Statement']['Principal']
    assume_role_type_value = "Service"
    assume_role_entity_value = "ec2"
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
    except Exception as e:
        return f"An error occurred: {e}"


# difference between aws service:
#
# {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Effect": "Allow",
#             "Action": [
#                 "sts:AssumeRole"
#             ],
#             "Principal": {
#                 "Service": "ec2.amazonaws.com"
#             }
#         }
#     ]
# }
#
# and aws account:
#
# {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Effect": "Allow",
#             "Action": "sts:AssumeRole",
#             "Principal": {
#                 "AWS": "762233763594"
#             },
#             "Condition": {}
#         }
#     ]
# }