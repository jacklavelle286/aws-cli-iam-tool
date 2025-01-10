# from . import json
# from . import iam_client
# from . import os

import boto3
import json
import os
iam_client = boto3.client("iam")

# TODO
# list iam users
# create iam user
# delete iam user

# interact with iam user:
# list policies
# add, delete policies
# change password
# get access keys
# revoke access keys
# assign MFA
# rotate access keys


def list_iam_users():
        response = iam_client.list_users()
        users = response.get("Users", [])
        user_names = [name['UserName'] for name in users]
        return user_names



# list attached polices for users (this will be reused)

def list_attached_user_policies(username, managed):
    if managed is True:
        attached_inline_policies_response = iam_client.list_user_policies(
            UserName=username
        )
        attached_inline_policies = attached_inline_policies_response.get("PolicyNames", [])
        return attached_inline_policies


    else:
        attached_managed_policies_response = iam_client.list_attached_user_policies(
            UserName=username
        )

        attached_managed_policies_response = attached_managed_policies_response.get("PolicyNames", [])
        return attached_managed_policies_response



def delete_iam_user(username):
    response = iam_client.delete_user(
        UserName=username
    )
    return response

