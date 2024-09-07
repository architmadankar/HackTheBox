# List of names
names = [
    "David Anderson",
    "Olivia Martinez",
    "Kevin Turner",
    "Amanda Walker",
    "Marcus Harris",
    "Lauren Clark",
    "Ethan Rodriguez"
]

# Generate usernames
def generate_usernames(name):
    first_name, last_name = name.lower().split()
    usernames = [
        f"{first_name}.{last_name}",
        f"{first_name[0]}{last_name}",
        f"{first_name}_{last_name}",
        f"{first_name[0]}{last_name[0]}",
        f"{first_name[0]}.{last_name}",
        f"{first_name}.{last_name[0]}",
        f"{first_name}{last_name}"
    ]
    return usernames

# Generate and write the username list
with open("users.txt", "w") as f:
    all_usernames = []
    for name in names:
        all_usernames.extend(generate_usernames(name))
    
    # Remove duplicates and sort
    all_usernames = sorted(set(all_usernames))
    
    # Output result with domain suffix
    for username in all_usernames:
        f.write(f"{username}@infiltrator.htb\n")

print("Done")
