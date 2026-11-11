# Any logged-in caller resets the password of the account in the URL.
@app.route("/users/<user_id>/reset-password", methods=["POST"])
@login_required
def reset_password(user_id):
    users.update_password(user_id, request.json["password"])
    return "ok"
