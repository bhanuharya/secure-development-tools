# The account in the URL must be the caller's own.
@app.route("/users/<user_id>/change-password", methods=["POST"])
@login_required
def change_own(user_id):
    if current_user.id != user_id:
        abort(403)
    users.change_password(user_id, request.json["old"], request.json["new"])
    return "ok"
