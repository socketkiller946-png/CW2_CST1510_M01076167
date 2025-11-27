import bcrypt
import os
import re

USER_DATA_FILE = "users.txt"

def hash_password(plain_text_password):
    # converting password to array of bytes
    bytes = plain_text_password.encode('utf-8')
    # generating the salt
    salt = bcrypt.gensalt()
    # Hashing the password
    hash = bcrypt.hashpw(bytes, salt)
    return hash.decode('utf-8')


def verify_password(plain_text_password, hashed_password):
    plainbytes = plain_text_password.encode('utf-8')
    hashbytes = hashed_password.encode('utf-8')
    result = bcrypt.checkpw(plainbytes, hashbytes)
    return result


def register_user(username, password):
    if user_exists(username):
        print(f"Error: Username '{username}' already exists.")
        return False
    hashed_password = hash_password(password)
    with open(USER_DATA_FILE, "a") as f:
        f.write(f"{username},{hashed_password}\n")
        print(f"User '{username}' registered.")
        return True


def user_exists(username):
    try:
        with open(USER_DATA_FILE, "r") as f:
            for line in f:
                if username in line:
                    return True
    except FileNotFoundError:
        return False
    return False


def login_user(username, password):
    try:
        with open(USER_DATA_FILE, "r") as f:
            for line in f.readlines():
                user, hash = line.strip().split(',', 1)
                if user == username:
                    if verify_password(password, hash):
                        print(f"Success: Welcome, {username}!")
                        return True
                    else:
                        print("Error: Invalid password.")
        print("Error: Username not found.")
        return False
    except FileNotFoundError:
        print("Error: Username not found.")
        return False




def validate_username(username):
    if len(username) < 3 or len(username) > 20:
        return False, "Username must be between 3 and 20 characters."
    if not username.isalnum():
        return False, "Username can only be alphanumeric."
    return True, ""



def validate_password(password):
    if len(password) < 3 or len(password) > 50:
        return False, "Password must be between 3 and 50 characters."
    return True, ""



def display_menu():
    """Displays the main menu options."""
    print("\n" + "="*50)
    print("  MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print("  Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)



def main():
    """Main program loop."""
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()

            # Validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            # Register the user
            register_user(username, password)

        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            # Attempt login
            if login_user(username, password):
                print("\nYou are now logged in.")
                print("(In a real application, you would now access the dashboard or main system features.)")

                # Optional: Ask if they want to logout or exit
                input("\nPress Enter to return to main menu...")

        elif choice == '3':
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()






