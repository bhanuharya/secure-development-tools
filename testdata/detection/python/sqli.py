from django.db import connection
from django.http import JsonResponse


def user(request):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s" % request.GET["id"])
    return JsonResponse({"rows": cursor.fetchall()})
