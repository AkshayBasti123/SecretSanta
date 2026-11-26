from flask import Flask, render_template, request, redirect, url_for, session
import json
import os
import random
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)


# Keep the Flask session key stable when the app restarts.
# For an online deployment, set SECRET_KEY in the hosting provider's settings.
def get_secret_key():
    secret_key = os.environ.get("SECRET_KEY")

    if secret_key:
        return secret_key

    key_file = ".secret_key"

    if os.path.exists(key_file):
        with open(key_file, "r") as file:
            return file.read().strip()

    secret_key = secrets.token_hex(32)

    with open(key_file, "w") as file:
        file.write(secret_key)

    return secret_key


app.secret_key = get_secret_key()


# Load and save groups
def load_groups():
    if os.path.exists("groups.json"):
        with open("groups.json", "r") as file:
            groups = json.load(file)

        # Add newer fields to groups created by an older version.
        for group in groups:
            group.setdefault("participant_tokens", {})
            group.setdefault("exclusions", {})
            group.setdefault("assignments", {})
            group.setdefault("drawn", False)

        return groups

    return []


def save_groups(groups):
    with open("groups.json", "w") as file:
        json.dump(groups, file, indent=4)


# Password helpers (organizer account only)
def hash_password(password):
    return generate_password_hash(password)


def check_password(password, stored_hash):
    return check_password_hash(stored_hash, password)


def is_organizer(group_code):
    return session.get("organizer_group") == group_code


def find_group(groups, group_code):
    return next(
        (group for group in groups if group["code"] == group_code),
        None
    )


# Homepage
@app.route("/")
def home():
    return render_template("index.html")


# Create a group
@app.route("/create", methods=["GET", "POST"])
def create_group():
    if request.method == "POST":
        group_name = request.form["group_name"].strip()
        organizer_password = request.form["organizer_password"]

        if not group_name:
            return "Please enter a group name."

        if len(organizer_password) < 8:
            return "Organizer password must be at least 8 characters."

        groups = load_groups()
        group_code = secrets.token_hex(3).upper()

        group = {
            "name": group_name,
            "code": group_code,
            "organizer_password": hash_password(organizer_password),
            "participants": [],
            "exclusions": {},
            "assignments": {},
            "participant_tokens": {},
            "drawn": False
        }

        groups.append(group)
        save_groups(groups)

        # The person who creates the group is automatically its organizer.
        session["organizer_group"] = group_code

        return redirect(url_for("group_page", group_code=group_code))

    return render_template("create.html")


# Show a group and its organizer-only participant links
@app.route("/group/<group_code>", methods=["GET", "POST"])
def group_page(group_code):
    groups = load_groups()
    group = find_group(groups, group_code)

    if group is None:
        return "Group not found."

    if request.method == "POST":
        if not is_organizer(group_code):
            return redirect(url_for(
                "organizer_login",
                group_code=group_code
            ))

        name = request.form["participant_name"].strip()

        if not group["drawn"] and name:
            already_exists = any(
                person.lower() == name.lower()
                for person in group["participants"]
            )

            if not already_exists:
                group["participants"].append(name)
                save_groups(groups)

        return redirect(url_for("group_page", group_code=group_code))

    participant_links = {}

    if is_organizer(group_code) and group["drawn"]:
        for participant, token in group.get("participant_tokens", {}).items():
            participant_links[participant] = url_for(
                "participant_reveal",
                group_code=group_code,
                token=token,
                _external=True
            )

    return render_template(
        "group.html",
        group=group,
        organizer_logged_in=is_organizer(group_code),
        participant_links=participant_links
    )


# Organizer login
@app.route("/group/<group_code>/organizer-login", methods=["GET", "POST"])
def organizer_login(group_code):
    groups = load_groups()
    group = find_group(groups, group_code)

    if group is None:
        return "Group not found."

    if request.method == "POST":
        password = request.form["organizer_password"]
        stored_hash = group.get("organizer_password")

        if stored_hash and check_password(password, stored_hash):
            session["organizer_group"] = group_code
            return redirect(url_for("group_page", group_code=group_code))

        return "Incorrect organizer password."

    return render_template("organizer_login.html", group=group)


# Log out the organizer
@app.route("/group/<group_code>/organizer-logout", methods=["POST"])
def organizer_logout(group_code):
    if is_organizer(group_code):
        session.pop("organizer_group", None)

    return redirect(url_for("group_page", group_code=group_code))


# Remove a participant
@app.route("/group/<group_code>/remove", methods=["POST"])
def remove_participant(group_code):
    groups = load_groups()
    group = find_group(groups, group_code)

    if group is None:
        return "Group not found."

    if not is_organizer(group_code):
        return redirect(url_for("organizer_login", group_code=group_code))

    name = request.form["participant_name"]

    if not group["drawn"] and name in group["participants"]:
        group["participants"].remove(name)
        group["exclusions"].pop(name, None)

        for person in group["exclusions"]:
            if name in group["exclusions"][person]:
                group["exclusions"][person].remove(name)

        save_groups(groups)

    return redirect(url_for("group_page", group_code=group_code))


# Add a two-way exclusion (for example, a couple)
@app.route("/group/<group_code>/exclude", methods=["POST"])
def add_exclusion(group_code):
    groups = load_groups()
    group = find_group(groups, group_code)

    if group is None:
        return "Group not found."

    if not is_organizer(group_code):
        return redirect(url_for("organizer_login", group_code=group_code))

    if group["drawn"]:
        return "The draw has already happened."

    person1 = request.form["person1"]
    person2 = request.form["person2"]

    if person1 not in group["participants"]:
        return "Invalid participant."

    if person2 not in group["participants"]:
        return "Invalid participant."

    if person1 == person2:
        return "A person cannot be excluded from themselves."

    exclusions = group["exclusions"]
    exclusions.setdefault(person1, [])
    exclusions.setdefault(person2, [])

    if person2 not in exclusions[person1]:
        exclusions[person1].append(person2)

    if person1 not in exclusions[person2]:
        exclusions[person2].append(person1)

    save_groups(groups)
    return redirect(url_for("group_page", group_code=group_code))


# Create a valid Secret Santa assignment
def create_draw(group):
    participants = group["participants"]
    exclusions = group["exclusions"]

    if len(participants) < 2:
        return None

    for attempt in range(10000):
        receivers = random.sample(participants, len(participants))
        assignments = {
            participants[index]: receivers[index]
            for index in range(len(participants))
        }

        valid = True

        for giver, receiver in assignments.items():
            if giver == receiver:
                valid = False
                break

            if receiver in exclusions.get(giver, []):
                valid = False
                break

        if valid:
            return assignments

    return None


# Run the draw and create a unique private link for every participant
@app.route("/group/<group_code>/draw", methods=["POST"])
def draw_group(group_code):
    groups = load_groups()
    group = find_group(groups, group_code)

    if group is None:
        return "Group not found."

    if not is_organizer(group_code):
        return redirect(url_for("organizer_login", group_code=group_code))

    if group["drawn"]:
        return "This group has already completed its draw."

    assignments = create_draw(group)

    if assignments is None:
        return (
            "No valid draw is possible. Check that there are enough "
            "participants and that the exclusions allow a valid draw."
        )

    group["assignments"] = assignments

    # Each participant gets a separate, randomly generated private token.
    # Only the organizer's group page displays these links.
    group["participant_tokens"] = {
        participant: secrets.token_urlsafe(32)
        for participant in group["participants"]
    }

    # A draw ID helps distinguish this draw from any future draw.
    group["draw_id"] = secrets.token_urlsafe(16)
    group["drawn"] = True

    save_groups(groups)

    return redirect(url_for("group_page", group_code=group_code))


# A participant opens their own private link to see their assignment.
@app.route("/group/<group_code>/reveal/<token>")
def participant_reveal(group_code, token):
    groups = load_groups()
    group = find_group(groups, group_code)

    if group is None:
        return "Group not found."

    if not group["drawn"]:
        return "This Secret Santa draw is not available."

    participant_name = None

    for name, saved_token in group.get("participant_tokens", {}).items():
        if secrets.compare_digest(saved_token, token):
            participant_name = name
            break

    if participant_name is None:
        return "This private link is invalid or no longer active."

    assigned_person = group.get("assignments", {}).get(participant_name)

    if assigned_person is None:
        return "This participant's assignment could not be found."

    return render_template(
        "participant_reveal.html",
        group=group,
        participant_name=participant_name,
        assigned_person=assigned_person
    )


if __name__ == "__main__":
    app.run(debug=True)
