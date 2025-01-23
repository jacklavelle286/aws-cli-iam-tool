from . import iam_client
from iam import iam_policy


def attach_user_policy(username, policy_arn):
    try:
        iam_client.attach_user_policy(UserName=username, PolicyArn=policy_arn)
        return f"Succesfully attached policy: {policy_arn}"
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No Such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate Limit exceeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failed: {e}")
        return None
    except iam_client.exceptions.InvalidInputException as e:
        print(f"Invalid input exception: {e}")
        return None
    except iam_client.exceptions.PolicyNotAttachableException as e:
        print(f"Policy not attachable: {e}")
        return None

class NoUsersFoundException(Exception):
    """Exception raised when no IAM users are found."""
    pass


def list_iam_users():
    try:
        response = iam_client.list_users()
        users = response.get("Users", [])
        user_list = [user['UserName'] for user in users]
        if not user_list:
            raise NoUsersFoundException("No IAM users found in the account.")
        return user_list
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failed: {e}. Try again later.")
        return []



def list_attached_managed_user_policies(username):
    try:
        attached_managed_policies_response = iam_client.list_attached_user_policies(UserName=username)
        attached_managed_policies = attached_managed_policies_response.get("AttachedPolicies", [])

        if not attached_managed_policies:  # Explicitly handle empty list
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No managed policies attached"}},
                operation_name="ListAttachedUserPolicies"
            )

        attached_managed = [policy["PolicyName"] for policy in attached_managed_policies]
        return attached_managed
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No policies attached to {username}: {e}"
    except iam_client.exceptions.InvalidInputException as e:
        return f"Invalid input: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure, try again later: {e}"


def list_attached_inline_user_policies(username):
    try:
        attached_inline_policies_response = iam_client.list_user_policies(UserName=username)
        attached_inline_policies = attached_inline_policies_response.get("PolicyNames", [])
        if not attached_inline_policies:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No inline policies attached"}},
                operation_name="ListAttachedUserPolicies"
            )
        return attached_inline_policies

    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No policies attached to {username}: {e}"
    except iam_client.exceptions.InvalidInputException as e:
        return f"Invalid input: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure, try again later: {e}"


def delete_user_policy(username, policy_name):
    try:
        iam_client.delete_user_policy(UserName=username, PolicyName=policy_name)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No Such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate Limit exceeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failed: {e}")
        return None

def list_access_keys(username):
    try:
        response = iam_client.list_access_keys(UserName=username)
        key_metadata = response.get("AccessKeyMetadata", [])
        if not key_metadata:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Access Keys found"}},
                operation_name="ListAccessKeys"
            )
        key_ids = [key['AccessKeyId'] for key in key_metadata]
        return key_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Request failure, try again later: {e}"




def list_certificate_ids(username):
    try:
        response = iam_client.list_signing_certificates(UserName=username)
        cert_metadata = response.get("Certificates", [])
        if not cert_metadata:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Certificates found"}},
                operation_name="ListSigningCertificates"
            )
        cert_ids = [cert['CertificateId'] for cert in cert_metadata]
        return cert_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Request failure, try again later: {e}"


def list_public_ssh_keys(username):
    try:
        response = iam_client.list_ssh_public_keys(UserName=username)
        key_metadata = response.get("SSHPublicKeys", [])
        if not key_metadata:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Public Keys found"}},
                operation_name="ListSSHPublicKeys"
            )
        key_ids = [key['SSHPublicKeyId'] for key in key_metadata]
        return key_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"

def list_service_specific_creds(username):
    try:
        response = iam_client.list_service_specific_credentials(UserName = username)
        creds = response.get("ServiceSpecificCredentials", [])
        if not creds:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Service specific creds found"}},
                operation_name="ListServiceSpecificCredentials"
            )
        cred_ids = [cred['ServiceSpecificCredentialId'] for cred in creds]
        return cred_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"
    except iam_client.exceptions.ServiceNotSupportedException as e:
        return f"Unsupported service: {e}"



def list_mfa_devices(username):
    try:
        response = iam_client.list_mfa_devices(UserName=username)
        devices = response.get("MFADevices", [])
        if not devices:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No MFA Devices found"}},
                operation_name="ListMFADevices"
            )
        device_ids = [device['SerialNumber'] for device in devices]
        return device_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"


def list_groups_for_user(username):
    try:
        groups = iam_client.list_groups_for_user(UserName=username)
        return [group['GroupName'] for group in groups.get("Groups", [])]
    except iam_client.exceptions.NoSuchEntityException:
        print(f"No groups found.")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Request failure, try again later: {e}")
        return None


def detach_user_policy(username, policy_arn):
    try:
        iam_client.detach_user_policy(UserName=username, PolicyArn=policy_arn)
        return f"successfully detached {policy_arn}."
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit succeeded: {e}")
        return None
    except iam_client.exceptions.InvalidInputException as e:
        print(f"Invalid input: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None

def delete_access_key(username, access_key_id):
    try:
        iam_client.delete_access_key(UserName=username, AccessKeyId=access_key_id)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit exceeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None


def delete_signing_certificate(username, cert):
    try:
        iam_client.delete_signing_certificate(UserName=username, CertificateId=cert)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit succeeded: {e}")
        return None
    except iam_client.exceptions.ConcurrentModificationException as e:
        print(f"Concurrent modification exception: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None


def delete_ssh_public_key(username, key_id):
    try:
        iam_client.delete_ssh_public_key(UserName=username, SSHPublicKeyId=key_id)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None


def delete_service_specific_creds(username, cred):
    try:
        iam_client.delete_service_specific_credential(UserName=username, ServiceSpecificCredentialId=cred)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None

def deactivate_mfa_device(username, serial_id):
    try:
        iam_client.deactivate_mfa_device(UserName=username, SerialNumber=serial_id)
    except iam_client.exceptions.EntityTemporarilyUnmodifiableException as e:
        print(f"Entity temporarily unmodifiable, try again later: {e}")
        return None
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit exceeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None
    except iam_client.exceptions.ConcurrentModificationException as e:
        print(f"Concurrent modification exception: {e}")
        return None

def delete_login_profile(username):
    try:
        iam_client.delete_login_profile(UserName=username)
        return "Login profile deleted successfully."
    except iam_client.exceptions.NoSuchEntityException:
        return "No login profile found for user."
    except iam_client.exceptions.EntityTemporarilyUnmodifiableException as e:
        print(f"Entity temporarily unmodifiable, try again later: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit exceeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None
    except iam_client.exceptions.ConcurrentModificationException as e:
        print(f"Concurrent modification exception: {e}")
        return None



def remove_user_from_group(username, group):
    try:
        iam_client.remove_user_from_group(UserName=username, GroupName=group)
        return "User removed from groups successfully. "
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit succeeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None

def delete_user(username):
    try:
        iam_client.delete_user(UserName=username)
        return f"Succesfully deleted {username}"
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limited exceeded: {e}")
        return None
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such user: {e}")
        return None
    except iam_client.exceptions.DeleteConflictException as e:
        print(f"Delete conflict, make sure everything is detached before deletion: {e}")
        return None
    except iam_client.exceptions.ConcurrentModificationException as e:
        print(f"Concurrent modification exception: {e}")
        return None
    except iam_client.exceptions.ConcurrentModificationException as e:
        print(f"Service failure: {e}")
        return None



# delete policies:

def delete_policies(username):
    print("Deleting attached policies...\n")
    managed_policies = list_attached_managed_user_policies(username=username)
    if managed_policies is None:
        print("Error retrieving managed policies. Skipping.\n")
    elif not managed_policies:
        print("No managed policies attached.\n")
    else:
        for policy in managed_policies:
            print(f"Detaching managed policies: {policy}\n")
            arn = iam_policy.get_iam_policy_arn(policy)
            detach_user_policy(username=username, policy_arn=arn)

    print("Deleting inline policies...\n")
    i_policies = list_attached_inline_user_policies(username=username)
    if i_policies is None:
        print("Error listing attached Inline policies. \n")
    elif not i_policies:
        print("No Inline policies attached. \n")
    else:
        for i_policy in i_policies:
            delete_user_policy(username=username, policy_name=i_policy)

# have to rewrite this to account for new error handling
def delete_iam_user(username):
    print("Deleting attached policies...\n")
    delete_policies(username=username)
    print("Deleting access keys...\n")
    key_list = list_access_keys(username)
    if key_list is None:
        print("Error listing keys. \n")
    elif not key_list:
        print("No Access keys found. \n")
    else:
        for key in key_list:
            print(f"Deleting: {key}\n")
            delete_access_key(username=username, access_key_id=key)

    print("Deleting certificates...\n")
    cert_ids = list_certificate_ids(username)
    if cert_ids is None:
        print("Error listing Cert IDs.\n")
    elif not cert_ids:
        print("No Certificates found.\n")
    else:
        for cert in cert_ids:
            print(f"Deleting: {cert}\n")
            delete_signing_certificate(username=username, cert=cert)

    print("Deleting SSH keys...\n")
    keys = list_public_ssh_keys(username=username)
    if keys is None:
        print("Error listing SSH keys.\n")
    elif not keys:
        print("No SSH keys found.\n")
    else:
        for key in keys:
            print(f"Deleting: {key}\n")
            delete_ssh_public_key(username=username, key_id=key)

    print("Deleting service-specific credentials...\n")
    creds = list_service_specific_creds(username)
    if creds is None:
        print("Error listing service-specific credentials.\n")
    elif not creds:
        print("No service-specific credentials found.\n")
    else:
        for cred in creds:
            print(f"Deleting: {cred}\n")
            delete_service_specific_creds(username=username, cred=cred)

    print("Deleting MFA devices...\n")
    devices_ids = list_mfa_devices(username)
    if devices_ids is None:
        print("Error listing MFA devices.\n")
    elif not devices_ids:
        print("No MFA devices found.\n")
    else:
        for serial_id in devices_ids:
            print(f"Deactivating: {serial_id}\n")
            deactivate_mfa_device(username=username, serial_id=serial_id)

    print("Deleting login profile...\n")
    delete_login_profile_response = delete_login_profile(username=username)
    if delete_login_profile_response is None:
        print("Error deleting login profile.\n")

    print("Removing user from groups...\n")
    users_groups = list_groups_for_user(username)
    if users_groups is None:
        print(f"Error listing {username}'s groups.\n")
    elif not users_groups:
        print("No groups found.\n")
    else:
        for group in users_groups:
            print(f"Removing user from group: {group}\n")
            remove_user_from_group(username=username, group=group)

    print("Deleting IAM user...\n")
    delete_user_response = delete_user(username=username)
    if delete_user_response:
        return f"Successfully deleted IAM user: {username}\n"
    else:
        return f"Failed to delete IAM user: {username}. Ensure all dependencies are removed.\n"



def create_iam_user(username):
    try:
        iam_client.create_user(UserName=username)
        return username
    except iam_client.exceptions.LimitExceededException as e:
        return f"Limit exceeded: {e}"
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        return f"IAM User already exists: {e}"
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No such entity exists: {e}"
    except iam_client.exceptions.InvalidInputException as e:
        return f"Invalid input: {e}"
    except iam_client.exceptions.ConcurrentModificationException as e:
        return f"Concurrent modification: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure: {e}"



# edit all functions to change error handling to deliver actual error code to main.py through returning the error string and checking ifinstance (function_output, str) then return error as if its a string then it's not a list for example
# start with detaching policies