import re
import math
import time
from datetime import datetime
import logging
from collections import Counter

# Initialize logging to track password checks and feedback
logging.basicConfig(filename='password_strength.log', level=logging.INFO)

# A mock list of common passwords (this would ideally be extended to 1000 or more common passwords)
common_passwords = [
    "123456", "password", "123456789", "12345678", "12345", "1234567", "1234567890", 
    "qwerty", "abc123", "password1", "111111", "iloveyou", "123123", "admin", "letmein",
    "welcome", "monkey", "football", "charlie", "sunshine", "whatever", "trustno1",
    "dragon", "hello", "freedom", "starwars", "ninja", "qazwsx", "654321", "superman"
]

# Additional features to keep track of login attempts for rate-limiting purposes
attempts = {}

class PasswordStrengthChecker:
    def __init__(self, password):
        self.password = password
        self.feedback = []
        self.score = 0
        self.attempt_count = 0
    
    def reset_feedback_and_score(self):
        self.feedback = []
        self.score = 0
    
    def check_length(self):
        """Evaluate password length and give feedback."""
        length = len(self.password)
        if length < 8:
            self.feedback.append("Password is too short. Minimum 8 characters are required.")
        elif 8 <= length <= 12:
            self.feedback.append("Password length is acceptable, but consider making it longer.")
            self.score += 1
        elif 13 <= length <= 16:
            self.feedback.append("Good password length.")
            self.score += 2
        else:
            self.feedback.append("Excellent password length.")
            self.score += 3
    
    def check_character_types(self):
        """Evaluate the use of various character types."""
        # Check for uppercase letters
        if re.search(r'[A-Z]', self.password):
            self.score += 1
        else:
            self.feedback.append("Add at least one uppercase letter.")
        
        # Check for lowercase letters
        if re.search(r'[a-z]', self.password):
            self.score += 1
        else:
            self.feedback.append("Add at least one lowercase letter.")
        
        # Check for digits
        if re.search(r'[0-9]', self.password):
            self.score += 1
        else:
            self.feedback.append("Add at least one number.")
        
        # Check for special characters
        if re.search(r'[\W_]', self.password):  # Non-alphanumeric characters
            self.score += 1
        else:
            self.feedback.append("Add at least one special character (e.g., !, @, #, $, etc.).")
    
    def check_common_password(self):
        """Check if the password is too common."""
        if self.password.lower() in common_passwords:
            self.feedback.append("Password is too common. Avoid using popular passwords.")
        else:
            self.score += 1
    
    def calculate_entropy(self):
        """Calculate entropy based on character variety and length."""
        character_set_size = 0
        if re.search(r'[a-z]', self.password):
            character_set_size += 26  # Lowercase letters
        if re.search(r'[A-Z]', self.password):
            character_set_size += 26  # Uppercase letters
        if re.search(r'[0-9]', self.password):
            character_set_size += 10  # Numbers
        if re.search(r'[\W_]', self.password):
            character_set_size += 33  # Special characters
        
        if character_set_size == 0:
            return 0
        
        # Entropy formula: L * log2(S)
        return len(self.password) * math.log2(character_set_size)
    
    def check_repeated_patterns(self):
        """Check for repeated patterns or characters."""
        if re.search(r'(.)\1{2,}', self.password):  # Repeated characters
            self.feedback.append("Avoid using more than two repeated characters in a row.")
            self.score -= 1

    def check_sequence_patterns(self):
        """Check for sequential patterns (like '123', 'abc')."""
        if re.search(r'(012|123|234|345|456|567|678|789|890)', self.password):
            self.feedback.append("Avoid using numeric sequences (e.g., '123').")
            self.score -= 1
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl)', self.password):
            self.feedback.append("Avoid using alphabetic sequences (e.g., 'abc').")
            self.score -= 1

    def brute_force_time_estimate(self):
        """Estimate time to crack the password using brute-force attacks."""
        entropy = self.calculate_entropy()
        # Time to crack = 2^entropy / attempts per second
        # Assume 1 billion guesses per second as a rough estimate
        attempts_per_second = 10**9
        time_to_crack_seconds = 2**entropy / attempts_per_second
        
        if time_to_crack_seconds < 60:
            self.feedback.append("This password could be cracked in less than a minute by a brute-force attack.")
        elif 60 <= time_to_crack_seconds < 3600:
            self.feedback.append(f"This password could be cracked in about {time_to_crack_seconds/60:.2f} minutes.")
        elif 3600 <= time_to_crack_seconds < 86400:
            self.feedback.append(f"This password could be cracked in about {time_to_crack_seconds/3600:.2f} hours.")
        else:
            self.feedback.append(f"This password is estimated to take {time_to_crack_seconds/86400:.2f} days to crack.")

    def rate_limiter(self, username):
        """Implements rate limiting to block excessive password checks."""
        current_time = time.time()
        if username in attempts:
            last_attempt_time, attempt_count = attempts[username]
            if current_time - last_attempt_time < 60:  # Limit to 1 attempt per minute
                self.feedback.append("Rate limit exceeded. Please wait before trying again.")
                return False
            else:
                attempts[username] = (current_time, attempt_count + 1)
        else:
            attempts[username] = (current_time, 1)
        return True

    def log_attempt(self, username):
        """Log password check attempts for auditing."""
        log_message = f"{datetime.now()} - User: {username}, Password Checked: {self.password}"
        logging.info(log_message)
    
    def educational_tips(self):
        """Provide tips for password security."""
        tips = [
            "Tip: Use a password manager to generate and store complex passwords.",
            "Tip: Never reuse passwords across multiple sites or services.",
            "Tip: Enable two-factor authentication (2FA) where available.",
            "Tip: Avoid using personal information (e.g., birthdates, names) in your password.",
            "Tip: Consider using passphrases with unrelated words (e.g., 'correcthorsebatterystaple')."
        ]
        self.feedback.append(tips)

    def provide_feedback(self):
        """Generate and display final feedback on password strength."""
        if self.score <= 2:
            self.feedback.append("Password strength: Weak.")
        elif 3 <= self.score <= 5:
            self.feedback.append("Password strength: Moderate.")
        else:
            self.feedback.append("Password strength: Strong.")

        # Display the feedback to the user
        for message in self.feedback:
            print(message)

    def check_password(self, username):
        """Run the full password check process."""
        if not self.rate_limiter(username):
            return
        self.reset_feedback_and_score()
        self.check_length()
        self.check_character_types()
        self.check_common_password()
        self.check_repeated_patterns()
        self.check_sequence_patterns()
        self.brute_force_time_estimate()
        self.educational_tips()
        self.provide_feedback()
        self.log_attempt(username)


class PasswordBlacklist:
    """A class to manage and update a blacklist of insecure or common passwords."""
    def __init__(self):
        self.blacklist = set(common_passwords)

    def is_blacklisted(self, password):
        """Check if the password is in the blacklist."""
        return password.lower() in self.blacklist

    def add_to_blacklist(self, password):
        """Add a password to the blacklist."""
        self.blacklist.add(password.lower())
    
    def update_blacklist(self, new_passwords):
        """Update the blacklist with a new batch of common passwords."""
        for pwd in new_passwords:
            self.blacklist.add(pwd.lower())

    def display_blacklist_size(self):
        """Display the size of the blacklist."""
        print(f"Current blacklist contains {len(self.blacklist)} passwords.")


# Example usage
if __name__ == "__main__":
    # Simulate a user checking their password strength
    username = input("Enter your username: ")
    password_input = input("Enter a password to test: ")

    # Initialize the password checker
    checker = PasswordStrengthChecker(password_input)
    checker.check_password(username)

    # Example of managing the blacklist
    blacklist_manager = PasswordBlacklist()
    blacklist_manager.display_blacklist_size()

    # Update blacklist with more common passwords
    additional_common_passwords = ["letmein", "trustno1", "123qwe", "passw0rd", "mypass"]
    blacklist_manager.update_blacklist(additional_common_passwords)
    blacklist_manager.display_blacklist_size()

    # Check if a specific password is blacklisted
    if blacklist_manager.is_blacklisted(password_input):
        print(f"The password '{password_input}' is blacklisted. Please choose a different one.")
