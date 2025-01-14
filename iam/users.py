from . import iam_client
from iam import iam_policy


# TODO

# change it so when with iam users either 1. create new one, or 2. you list the iam users, choose one, then choose what operations you want to do i.e add policies, remove, delete etc etc
# create iam user

# interact with iam user:
# list policies
# add, delete policies
# change password
# get access keys
# revoke access keys
# assign MFA
# rotate access keys


# add extensive error handling within the functions themselves


def list_iam_users():
    try:
        response = iam_client.list_users()
        users = response.get("Users", [])
        return [user['UserName'] for user in users]
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failed: {e}. Try again later.", []
    except Exception as e:
        print(f"Service failed. {e} - try again later.")
        return []


def list_attached_user_policies(username, managed):
    if managed:
        try:
            attached_managed_policies_response = iam_client.list_attached_user_policies(UserName=username)
        except iam_client.list_attached_user_policies.NoSuchEntityException as e:
            return "No policies attached to {username}: {e}", []
        except iam_client.list_attached_user_policies.InvalidInputException as e:
            return f"Invalid input: {e}", []
        except iam_client.list_attached_user_policies.ServiceFailureException as e:
            return f"Service failure, try again later: {e}", []

        attached_managed_policies = attached_managed_policies_response.get("AttachedPolicies", [])
        return [policy["PolicyName"] for policy in attached_managed_policies]
    else:
        attached_inline_policies_response = iam_client.list_user_policies(
            UserName=username
        )
        attached_inline_policies = attached_inline_policies_response.get("PolicyNames", [])
        return attached_inline_policies


def list_access_keys(username):
    try:
        access_keys = iam_client.list_access_keys(UserName=username)
        key_ids = [key['AccessKeyId'] for key in access_keys.get("AccessKeyMetadata", [])]
        return key_ids
    except iam_client.list_access_keys.NoSuchEntityException as e:
        return f"No Access Keys found: {e}", []
    except iam_client.list_access_keys.ServiceFailureException as e:
        return f"Request failure, try again later: {e}"

# start here

def list_certificate_ids(username):
    try:
        certificates = iam_client.list_signing_certificates(UserName=username)
        cert_ids = [cert['CertificateId'] for cert in certificates.get('Certificates', [])]
        return cert_ids
    except iam_client.list_signing_certificates.NoSuchEntityException:
        return f"No certificates found.", []
    except iam_client.list_signing_certificates.ServiceFailureException as e:
        return f"Request failure, try again later: {e}"


def list_public_ssh_keys(username):
    try:
        keys = iam_client.list_ssh_public_keys(UserName = username)
        key_ids = [key['SSHPublicKeyId'] for key in keys.get('SSHPublicKeys', [])]
        return key_ids
    except iam_client.list_ssh_public_keys.NoSuchEntityException as e:
        return f"No publish SSH keys found: {e}", []

def list_service_specific_creds(username):
    try:
        creds = iam_client.list_service_specific_credentials(UserName = username)
        cred_ids = [cred['ServiceSpecificCredentialId'] for cred in creds.get('ServiceSpecificCredentials', [])]
        return cred_ids
    except iam_client.list_service_specific_credentials.NoSuchEntityException as e:
        return f"No credentials found: {e}", []
    except iam_client.list_service_specific_credentials.ServiceNotSupportedException as e:
        return f"Unsupported service: {e}"



def list_mfa_devices(username):
    try:
        devices = iam_client.list_mfa_devices(UserName=username)
        device_ids = [device['SerialNumber'] for device in devices.get('MFADevices', [])]
        return device_ids
    except iam_client.list_mfa_devices.NoSuchEntityException as e:
        return f"No MFA devices found: {e}", []

def list_groups_for_user(username):
    try:
        groups = iam_client.list_groups_for_user(UserName=username)
        return [group['GroupName'] for group in groups.get("Groups", [])]
    except iam_client.list_groups_for_user.NoSuchEntityException:
        return f"No groups found.", []
    except iam_client.list_groups_for_user.ServiceFailureException as e:
        return f"Request failure, try again later: {e}"

# edit the below function to take the following and put into their own function:

# "call delete signing cert function"
# "call delete ssh publish key function"
# "call delete service specific cred function"
# "call deactivate mfa function"
# "call delete login profile function"
# "call remove user from group function"


def delete_iam_user(username):
    print("Deleting attached policies...")
    policies = list_attached_user_policies(username=username, managed=True)
    for policy in policies:
        print(f"Deleting: {policy}")
    policy_arns = []
    for name in policies:
        arn = iam_policy.get_iam_policy_arn(name)
        policy_arns.append(arn)
    for arn in policy_arns:
        iam_client.detach_user_policy(UserName=username, PolicyArn=arn)
    print("Deleting inline policies...")
    inline_policies = list_attached_user_policies(username=username, managed=False)
    for i_policy in inline_policies:
        print(f"Deleting: {i_policy}")
        iam_client.delete_user_policy(PolicyName=i_policy,UserName=username)
    print("Deleting access keys...")
    key_list = list_access_keys(username)
    for key in key_list:
        print(f"Deleting: {key}")
        iam_client.delete_access_key(UserName=username, AccessKeyId=key)
    print("Deleting certificates..")
    cert_ids = list_certificate_ids(username)
    for cert in cert_ids:
        print(f"Deleting: {cert}")
        # call delete signing cert function
        iam_client.delete_signing_certificate(UserName=username, CertificateId=cert)
    print("Deleting Public SSH Keys...")
    keys = list_public_ssh_keys(username=username)
    for key in keys:
        print(key)
        print(f"Deleting: {key}")
        # call delete ssh publish key function
        iam_client.delete_ssh_public_key(UserName=username, SSHPublicKeyId=key)
    print("Deleting Public Git Credentials...")
    creds = list_service_specific_creds(username)
    for cred in creds:
        print(f"Deleting: {cred}")
        # call delete service specfic cred function
        iam_client.delete_service_specific_credential(UserName=username, ServiceSpecificCredentialId=cred)
    print("Deleting MFA Devices...")
    devices_ids = list_mfa_devices(username)
    for ids in devices_ids:
        print(f"Deactivating: {ids}")
        # call deactivate mfa function
        iam_client.deactivate_mfa_device(UserName=username, SerialNumber=id)
    print("Deleting Login Profile...")
    # call delete login profile function
    iam_client.delete_login_profile(UserName=username)
    users_groups = list_groups_for_user(username)
    for group in users_groups:
        print(f"Removing user from group: {group}")
        # call remove user from group function
        iam_client.remove_user_from_group(UserName=username, GroupName=group)
    print("Deleting user...")
    iam_client.delete_user(UserName=username)
    print("User Deleted!")



