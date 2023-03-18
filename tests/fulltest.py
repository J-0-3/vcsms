import importlib
import os

test_sets = []
print("Loading test sets...")
for file in os.listdir("tests"):
    if file[-3:] == ".py":
        print(f"Loading test set: {file[:-3]}")
        test_module = importlib.import_module(f"tests.{file[:-3]}")
        test_sets.append(test_module.tests)

for set in test_sets:
    set.run()
    
