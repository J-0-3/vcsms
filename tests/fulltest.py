import importlib
import os

test_sets = []
for file in os.listdir("tests"):
    if file[-3:] == ".py":
        test_module = importlib.import_module(f"tests.{file[:-3]}")
        test_sets.append(test_module.tests)

for set in test_sets:
    set.run_all()
    
