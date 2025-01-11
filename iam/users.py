# from . import json
# from . import iam_client
# from . import os

import boto3
import json
import os

from iam import iam_policy

iam_client = boto3.client("iam")



# TODO

# change it so when with iam users either 1. create new one, or 2. you list the iam users, choose one, then choose what operations you want to do i.e add policies, remove, delete etc etc
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
    if managed:
        attached_managed_policies_response = iam_client.list_attached_user_policies(
            UserName=username
        )
        attached_managed_policies = attached_managed_policies_response.get("AttachedPolicies", [])
        return [policy["PolicyName"] for policy in attached_managed_policies]
    else:
        attached_inline_policies_response = iam_client.list_user_policies(
            UserName=username
        )
        attached_inline_policies = attached_inline_policies_response.get("PolicyNames", [])
        return attached_inline_policies

def list_access_keys(username):
    access_keys = iam_client.list_access_keys(UserName=username)
    key_ids = [key['AccessKeyId'] for key in access_keys.get("AccessKeyMetadata", [])]
    return key_ids



def list_certificate_ids(username):
    certificates = iam_client.list_signing_certificates(UserName=username)
    cert_ids = [cert['CertificateId'] for cert in certificates.get('Certificates', [])]
    return cert_ids



def delete_iam_user(username):
    # list all attached policies
    print("Deleting attached policies...")
    policies = list_attached_user_policies(username=username, managed=True)
    for policy in policies:
        print(policy)
    # get arn for each policy
    policy_arns = []
    for name in policies:
        arn = iam_policy.get_iam_policy_arn(name)
        policy_arns.append(arn)
    # detach user policies

    for arn in policy_arns:
        iam_client.detach_user_policy(UserName=username, PolicyArn=arn)
    # detach Inline policies(DeleteUserPolicy)
    # get inline policies:
    inline_policies = list_attached_user_policies(username=username, managed=False)
    for i_policy in inline_policies:
        print(i_policy)
        iam_client.delete_user_policy(PolicyName=i_policy,UserName=username)
    print("Deleting access keys...")
    # Access keys(DeleteAccessKey)
    #list access keys
    key_list = list_access_keys(username)
    for key in key_list:
        print(key)
        iam_client.delete_access_key(UserName=username, AccessKeyId=key)
    print("Deleting certificates..")
    # certificate(DeleteSigningCertificate)
    cert_ids = list_certificate_ids(username)
    for cert in cert_ids:
        print(cert)
        iam_client.delete_signing_certificate(UserName=username, CertificateId=cert)
    # SSH publickey(DeleteSSHPublicKey)
    # Git credentials(DeleteServiceSpecificCredential)
    # Multi - factor authentication(MFA)device(DeactivateMFADevice, DeleteVirtualMFADevice)
    # Password(DeleteLoginProfile)
    #iam_client.delete_login_profile(UserName=username)
    # Inline policies(DeleteUserPolicy)
    # Group emberships(RemoveUserFromGroup)
    # delete user:
    iam_client.delete_user


