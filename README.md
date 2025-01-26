# AWS PyIAM Tool

## Description
The **AWS PyIAM Tool** simplifies the management of AWS Identity and Access Management (IAM) policies, users, roles, and groups. Writing JSON policy documents manually can be tedious and error-prone when using the AWS CLI. This tool provides an intuitive, 
Python-based wrapper to make IAM management faster and easier. It is based upon the `boto-3` Python sdk from AWS. 

---

## The Problem Statement
Managing IAM resources using the AWS CLI can be complex and time-consuming, especially when writing and managing JSON policy documents manually. The **AWS CLI IAM Tool** solves these problems by:
- Providing an interactive interface for creating and managing IAM resources, this build JSON documents via a CLI tool based on user input to get perfectly formatted, well written polices.
- Reducing the time, effort, and errors associated with managing IAM - maintaining security in the process.



## Features

### IAM Policies
- **Create IAM Policies**:
  - Guided prompts for defining policy details such as SID, effect, actions, and resources.
  - Supports multiple `Statement` blocks interactively within a single policy.
  - Saves policies as JSON files locally and creates them directly in AWS, to optionally overwrite policies with the same name in AWS.
  
- **List IAM Policies**:
  - View all customer-managed policies in AWS.
  - List locally stored policies for easy management.

- **Delete IAM Policies**:
  - Delete a specific local policy file or all local policy files at once.
  - Detach and delete policies directly in AWS.

### IAM Users
- **Create IAM Users**:
  - Guided input to create new IAM users.


- **List IAM Users**:
  - Retrieve a list of all existing IAM users with detailed attributes.
  - List both managed and inline policies for IAM users.

- **Delete IAM Users**:
  - Remove users interactively or in bulk, ensuring associated resources (e.g., policies) are detached first.

### IAM Groups
- **Create IAM Groups**:
  - Easily create groups and attach policies and add users into Groups.

- **List IAM Groups**:
  - View all existing groups and their associated policies.

- **Delete IAM Groups**:
  - Safely delete groups and associated resources.

### IAM Roles
- **Create IAM Roles**:
  - Define trust relationships and attach policies through guided input.

- **List IAM Roles**:
  - Retrieve all roles and their details.

- **Delete IAM Roles**:
  - Remove roles safely, ensuring associated resources are detached.

- **Single Command to Assume IAM Roles**:
  - Through simply passing the role name when you are locally authenticated as an IAM user, you can Assume any role you have permissions to assume. 
---


---

## Future Vision
The tool is being developed into a fully-fledged CLI application with:
- Installation via `pip` (`pip install aws-cli-iam-tool`).
- Use of a library like `prompt_toolkit` to improve user experience
- Tab-completion for easier navigation.

---




