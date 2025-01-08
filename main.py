from iam import policy


# Main Program Execution for policy.py

def main():
    print(r"""
      __          _______   _____          __  __   _____       _   _                  __          __                              
     /\ \        / / ____| |_   _|   /\   |  \/  | |  __ \     | | | |                 \ \        / /                              
    /  \ \  /\  / / (___     | |    /  \  | \  / | | |__) |   _| |_| |__   ___  _ __    \ \  /\  / / __ __ _ _ __  _ __   ___ _ __ 
   / /\ \ \/  \/ / \___ \    | |   / /\ \ | |\/| | |  ___/ | | | __| '_ \ / _ \| '_ \    \ \/  \/ / '__/ _` | '_ \| '_ \ / _ \ '__|
  / ____ \  /\  /  ____) |  _| |_ / ____ \| |  | | | |   | |_| | |_| | | | (_) | | | |    \  /\  /| | | (_| | |_) | |_) |  __/ |   
 /_/    \_\/  \/  |_____/  |_____/_/    \_\_|  |_| |_|    \__, |\__|_| |_|\___/|_| |_|     \/  \/ |_|  \__,_| .__/| .__/ \___|_|   
                                                           __/ |                                            | |   | |              
                                                          |___/                                             |_|   |_|              

    """)

    print("Welcome to the IAM Python Wrapper")
    while True:
        choice = input("Do you want to work with IAM Policies, Users, Roles or Groups?: (1,2,3 or 4) or press 'q' to quit the programme. ").lower()
        if choice == "1":
            print("Moving to IAM Polices..")
            policy.user_inputs = policy.get_user_input_policy()
            policy.policy_file_name = policy.create_iam_policy_file(policy.user_inputs)
            policy.create_policy(policy.policy_file_name)
        elif choice == "q":
            print("Exiting the programme..")
            exit()

if __name__ == "__main__":
    main()
