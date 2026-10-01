"""Cross-function taint demo: user input flows through a helper into a sink.

Single-function analysis cannot connect the source (request input) to the
sink (os.system) because they live in different functions of the same file.
Intra-file inter-procedural taint (--taint-intrafile) should flag it.
"""
import os


def get_user_name(request):
    return request.GET.get("name", "")


def build_greeting(name):
    return "hello " + name


def greet_view(request):
    name = get_user_name(request)
    greeting = build_greeting(name)
    os.system("echo " + greeting)  # SDT-EXPECT: sast finding (tainted os.system)
