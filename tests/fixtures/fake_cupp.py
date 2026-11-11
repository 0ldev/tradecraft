#!/usr/bin/env python3
"""A fake, minimal stand-in for cupp.py -i, used only by test_cupp.py to
drive the real pexpect interaction end-to-end without a real cupp
install. Mirrors two real quirks confirmed against a live cupp.py run
(see tradecraft/adapters/cupp/execute.py's module docstring): the
"keywords" step is two separate prompts (a Y/[N] gate, then -- only if
answered y -- a second prompt for the actual words), and a final
"Hyperspeed Print?" prompt that isn't part of the documented field set.
Also asks its questions in a different order than tradecraft's own prompt
table expects, to prove the keyword-matching doesn't depend on order.
"""
from __future__ import annotations

answers = {}
answers["company"] = input("> What is the company name? : ")
answers["surname"] = input("> Insert the surname: ")
answers["name"] = input("> Insert the name: ")
answers["pet_name"] = input("> Do you want to add the pet's name? : ")

keywords_gate = input("> Do you want to add some key words about the victim? Y/[N]: ")
if keywords_gate.strip().lower() == "y":
    answers["keywords"] = input("Please enter the words, separated by comma: ")
else:
    answers["keywords"] = ""

answers["leet"] = input("> Do you want to enable leet mode (i.e. leet = 1337)? Y/[N]: ")
input("> Hyperspeed Print? (Y/n): ")

with open("fake_output.txt", "w") as f:
    for value in answers.values():
        if value:
            f.write(value + "\n")
    f.write(f"{answers.get('name', '')}{answers.get('surname', '')}\n")
